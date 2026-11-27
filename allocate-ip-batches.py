"""Read IP and service from columns A and B of an Excel sheet and assign batches."""

import argparse
import csv
from fractions import Fraction
from ipaddress import ip_address
from math import gcd
from pathlib import Path
from zipfile import BadZipFile

import networkx as nx
from openpyxl import load_workbook
from openpyxl.utils.exceptions import InvalidFileException


DEFAULT_BATCH_WEIGHTS = (1, 3, 6)


def parse_ratios(value):
    shares = []
    try:
        for part in value.replace("，", ",").split(","):
            percent = part.strip()
            if percent.endswith("%"):
                percent = percent[:-1].strip()
            shares.append(Fraction(percent) / 100)
    except (ValueError, ZeroDivisionError) as error:
        raise argparse.ArgumentTypeError("请输入逗号分隔的百分比，例如 10,30,60。") from error
    if any(share < 0 for share in shares) or sum(shares) != 1:
        raise argparse.ArgumentTypeError("各批次比例须大于或等于 0，且合计为 100%。")

    scale = 1
    for share in shares:
        scale = scale // gcd(scale, share.denominator) * share.denominator
    return tuple(share.numerator * (scale // share.denominator) for share in shares)


def marginal_costs(size, weight, scale):
    """Compress the marginal costs of abs(scale * count - weight * size)."""
    floor, remainder = divmod(weight * size, scale)
    if floor:
        yield floor, -scale
    if remainder:
        yield 1, scale - 2 * remainder
    remaining = size - floor - bool(remainder)
    if remaining:
        yield remaining, scale


def allocate_counts(service_sizes, batch_weights=DEFAULT_BATCH_WEIGHTS):
    """Fix exact splits, maximize first-batch coverage, then minimize deviation."""
    scale = sum(batch_weights)
    total = sum(service_sizes.values())
    early_targets = tuple(weight * total // scale for weight in batch_weights[:-1])
    targets = (*early_targets, total - sum(early_targets))

    allocations = {}
    remaining_targets = list(targets)
    flexible = {}
    for service, size in service_sizes.items():
        quotas = [divmod(weight * size, scale) for weight in batch_weights]
        if any(remainder for _, remainder in quotas):
            flexible[service] = size
        else:
            exact = tuple(count for count, _ in quotas)
            allocations[service] = exact
            for batch, count in enumerate(exact):
                remaining_targets[batch] -= count

    if not flexible:
        return allocations, targets

    graph = nx.MultiDiGraph()
    for batch, demand in enumerate(remaining_targets):
        graph.add_node(batch, demand=demand)

    # One more covered service takes precedence over every possible rounding gain.
    coverage_reward = 2 * scale * sum(flexible.values()) + 1
    for service, size in flexible.items():
        source = ("service", service)
        graph.add_node(source, demand=-size)
        for batch, weight in enumerate(batch_weights):
            segments = list(marginal_costs(size, weight, scale))
            if batch == 0 and size >= 2:
                capacity, unit_cost = segments.pop(0)
                graph.add_edge(source, batch, capacity=1, weight=unit_cost - coverage_reward)
                if capacity > 1:
                    segments.insert(0, (capacity - 1, unit_cost))
            for capacity, unit_cost in segments:
                graph.add_edge(source, batch, capacity=capacity, weight=unit_cost)

    _, flow = nx.network_simplex(graph)
    for service in flexible:
        outgoing = flow[("service", service)]
        allocations[service] = tuple(sum(outgoing[batch].values()) for batch in range(len(batch_weights)))
    return allocations, targets


def read_excel(path, sheet_name):
    workbook = load_workbook(path, read_only=True, data_only=True)
    try:
        if sheet_name is not None and sheet_name not in workbook.sheetnames:
            raise ValueError(f"找不到工作表 {sheet_name!r}。")
        sheet = workbook[sheet_name] if sheet_name is not None else workbook.worksheets[0]
        rows = sheet.iter_rows(values_only=True)
        header = next(rows, ())
        if len(header) < 2 or any(v is None or not str(v).strip() for v in header[:2]):
            raise ValueError("第一行须为表头，A 列为 IP，B 列为归属服务。")
        if "批次" in header:
            raise ValueError("表中已有“批次”列。请使用待分批的原始表。")

        records = []
        owners = {}
        last_batch_ips = set()
        for row_number, row in enumerate(rows, start=2):
            if all(value is None or value == "" for value in row):
                continue
            address, owner = row[:2]
            if address is None or not str(address).strip():
                raise ValueError(f"第 {row_number} 行缺少 IP。")
            try:
                address_key = ip_address(str(address).strip())
            except ValueError as error:
                raise ValueError(f"第 {row_number} 行不是有效的 IP 地址：{address!r}。") from error
            records.append((address_key, row))
            service = "" if owner is None else str(owner).strip()
            if not service:
                last_batch_ips.add(address_key)
                continue
            previous = owners.get(address_key)
            if previous is None:
                owners[address_key] = (service, row_number)
            elif previous[0] != service:
                raise ValueError(f"IP {address_key} 同时属于 {previous[0]!r}（第 {previous[1]} 行）"
                                 f"和 {service!r}（第 {row_number} 行）。")
        if not records:
            raise ValueError("工作表里没有 IP 记录。")

        services = {}
        for address_key, (service, _) in owners.items():
            if address_key not in last_batch_ips:
                services.setdefault(service, []).append(address_key)
        return header, records, services, last_batch_ips
    finally:
        workbook.close()


def main():
    parser = argparse.ArgumentParser(description="按总量上限和服务内目标比例给 IP 分批，默认比例为 10%、30%、60%。")
    parser.add_argument("input", type=Path, help="源 Excel 文件。第一行是表头，A 列为 IP，B 列为归属服务。")
    parser.add_argument("output", type=Path, help="新的 CSV 文件，供 Excel 打开。")
    parser.add_argument("--sheet", help="工作表名称，默认读取第一个工作表。")
    batch_options = parser.add_mutually_exclusive_group()
    batch_options.add_argument("--batches", type=int, help="按相同比例分成指定的批次数，例如 10。")
    batch_options.add_argument("--ratios", type=parse_ratios, help="各批次的百分比，用逗号分隔，合计百分之百，例如 10,30,60。")
    args = parser.parse_args()
    if args.output.suffix.lower() != ".csv":
        parser.error("输出文件名须以 .csv 结尾。")
    if args.batches is not None:
        if args.batches < 1:
            parser.error("--batches 必须是大于 0 的整数。")
        batch_weights = (1,) * args.batches
    else:
        batch_weights = args.ratios or DEFAULT_BATCH_WEIGHTS
    last_batch = len(batch_weights)

    try:
        header, records, services, last_batch_ips = read_excel(args.input, args.sheet)
        counts, targets = allocate_counts(
            {service: len(addresses) for service, addresses in services.items()}, batch_weights
        )

        # Use the same batch for every row of an IP, including mixed blank and known rows.
        assigned = dict.fromkeys(last_batch_ips, last_batch)
        for service, addresses in services.items():
            start = 0
            for batch, count in enumerate(counts[service], start=1):
                end = start + count
                for address in addresses[start:end]:
                    assigned[address] = batch
                start = end

        with args.output.open("x", newline="", encoding="utf-8-sig") as output:
            writer = csv.writer(output)
            writer.writerow((*header, "批次"))
            for address, row in records:
                writer.writerow((*row, assigned[address]))
    except FileExistsError:
        parser.exit(1, f"输出文件已存在：{args.output}\n")
    except (OSError, ValueError, InvalidFileException, BadZipFile) as error:
        parser.exit(1, f"分批失败：{error}\n")

    total = len(assigned)
    print(f"共 {total} 个唯一 IP，按归属参与分配的服务有 {len(services)} 个。")
    for batch, count in enumerate((*targets[:-1], targets[-1] + len(last_batch_ips)), start=1):
        print(f"第 {batch} 批：{count} 个，占 {count / total:.1%}")
    if last_batch_ips:
        print(f"归属服务为空而直接分到第 {last_batch} 批的唯一 IP 有 {len(last_batch_ips)} 个。")
    multi_ip_services = [service for service, addresses in services.items() if len(addresses) >= 2]
    covered = sum(counts[service][0] > 0 for service in multi_ip_services)
    print(f"第一批覆盖 {covered}/{len(multi_ip_services)} 个至少有两个 IP 的服务。")
    duplicates = len(records) - total
    if duplicates:
        print(f"保留了 {duplicates} 行重复 IP，重复行使用同一批次。")
    print(f"结果已保存到 {args.output}")


if __name__ == "__main__":
    main()

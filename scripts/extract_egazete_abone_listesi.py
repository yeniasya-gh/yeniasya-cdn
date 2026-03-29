#!/usr/bin/env python3
import json
import sys
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path


NS = {"main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
EXCEL_EPOCH = datetime(1899, 12, 30)


def read_shared_strings(zf: zipfile.ZipFile) -> list[str]:
    if "xl/sharedStrings.xml" not in zf.namelist():
        return []
    root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
    shared: list[str] = []
    for si in root.findall("main:si", NS):
        parts = []
        for node in si.iter("{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t"):
            parts.append(node.text or "")
        shared.append("".join(parts))
    return shared


def cell_text(cell: ET.Element, shared: list[str]) -> str:
    cell_type = cell.attrib.get("t")
    value = cell.find("main:v", NS)
    if value is not None and value.text is not None:
        if cell_type == "s":
            index = int(value.text)
            return shared[index] if 0 <= index < len(shared) else ""
        return value.text

    inline = cell.find("main:is", NS)
    if inline is not None:
        parts = []
        for node in inline.iter("{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t"):
            parts.append(node.text or "")
        return "".join(parts)
    return ""


def parse_date(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        raise ValueError("empty date")

    try:
        serial = float(raw)
        dt = EXCEL_EPOCH + timedelta(days=serial)
        return dt.date().isoformat()
    except ValueError:
        pass

    for fmt in ("%Y-%m-%d", "%d.%m.%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(raw, fmt).date().isoformat()
        except ValueError:
            continue

    raise ValueError(f"Unsupported date format: {raw}")


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: extract_egazete_abone_listesi.py <xlsx-path>", file=sys.stderr)
        return 2

    xlsx_path = Path(sys.argv[1]).expanduser().resolve()
    if not xlsx_path.exists():
        print(f"File not found: {xlsx_path}", file=sys.stderr)
        return 2

    with zipfile.ZipFile(xlsx_path) as zf:
        shared = read_shared_strings(zf)
        root = ET.fromstring(zf.read("xl/worksheets/sheet1.xml"))

    rows = []
    headers = None
    for row in root.findall(".//main:sheetData/main:row", NS):
        values = []
        for cell in row.findall("main:c", NS):
            values.append(cell_text(cell, shared))
        if headers is None:
            headers = values
            continue

        record = {headers[i]: values[i] if i < len(values) else "" for i in range(len(headers))}
        if record.get("Durum", "").strip().lower() != "aktif":
            continue

        name = record.get("İsim", "").strip()
        email = record.get("E-posta", "").strip().lower()
        starts_at = parse_date(record.get("Üye olma", ""))
        ends_at = parse_date(record.get("Abonelik bitişi", ""))

        if not name or not email:
            raise ValueError(f"Missing name/email in active row: {record}")
        if starts_at >= ends_at:
            raise ValueError(f"Invalid date range for {email}: {starts_at} -> {ends_at}")

        rows.append(
            {
                "name": name,
                "email": email,
                "starts_at": starts_at,
                "ends_at": ends_at,
                "status": "old",
            }
        )

    payload = {"activeCount": len(rows), "rows": rows}
    json.dump(payload, sys.stdout, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

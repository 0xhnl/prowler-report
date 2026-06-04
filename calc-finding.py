import argparse
import sys
import pandas as pd
from pathlib import Path

parser = argparse.ArgumentParser(description="Aggregate Prowler findings from a CSV into an XLSX report.")
parser.add_argument("-f", "--file", required=True, help="Input CSV file (.csv)")
parser.add_argument("-o", "--output", required=True, help="Output XLSX file (.xlsx)")
args = parser.parse_args()

SRC = Path(args.file)
OUT = Path(args.output)

if SRC.suffix.lower() != ".csv":
    sys.exit(f"Error: input file must be a .csv file, got '{SRC.name}'")
if OUT.suffix.lower() != ".xlsx":
    sys.exit(f"Error: output file must be a .xlsx file, got '{OUT.name}'")
if not SRC.is_file():
    sys.exit(f"Error: input file not found: {SRC}")

df = pd.read_csv(SRC)

by_service = (
    df.pivot_table(index="Service Name", columns="Status", aggfunc="size", fill_value=0)
      .assign(Total=lambda d: d.sum(axis=1))
      .sort_values("FAIL", ascending=False)
      .reset_index()
)

by_region = (
    df.pivot_table(index="Region", columns="Status", aggfunc="size", fill_value=0)
      .assign(Total=lambda d: d.sum(axis=1))
      .sort_values("FAIL", ascending=False)
      .reset_index()
)

fail_service_region = (
    df[df["Status"] == "FAIL"]
      .pivot_table(index="Service Name", columns="Region", aggfunc="size", fill_value=0)
)
fail_service_region["Total"] = fail_service_region.sum(axis=1)
fail_service_region = fail_service_region.sort_values("Total", ascending=False).reset_index()

with pd.ExcelWriter(OUT, engine="openpyxl") as writer:
    by_service.to_excel(writer, sheet_name="By Service", index=False)
    by_region.to_excel(writer, sheet_name="By Region", index=False)
    fail_service_region.to_excel(writer, sheet_name="FAIL Service x Region", index=False)

    for sheet_name, frame in [
        ("By Service", by_service),
        ("By Region", by_region),
        ("FAIL Service x Region", fail_service_region),
    ]:
        ws = writer.sheets[sheet_name]
        for col_idx, col in enumerate(frame.columns, start=1):
            width = max(len(str(col)), *(len(str(v)) for v in frame[col].astype(str))) + 2
            ws.column_dimensions[ws.cell(row=1, column=col_idx).column_letter].width = min(width, 40)

print(f"Wrote {OUT}")
print(f"Services: {len(by_service)} | Regions: {len(by_region)}")

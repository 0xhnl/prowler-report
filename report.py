import argparse
import re
from pathlib import Path

import pandas as pd
from bs4 import BeautifulSoup
from docx import Document


HTML_COLUMNS_TO_EXTRACT = [0, 1, 2, 3, 5, 6, 8, 9, 10]
CSV_HEADER = [
    "Status",
    "Severity",
    "Service Name",
    "Region",
    "Check Title",
    "Resource ID",
    "Status Extended",
    "Risk",
    "Recommendation",
]


def clean_text(text):
    """Remove HTML artifacts and normalize whitespace."""
    text = text.replace("<wbr />", "")
    soup = BeautifulSoup(text, "html.parser")
    text = soup.get_text(separator=" ", strip=True)
    return re.sub(r"\s+", " ", text).strip()


def parse_prowler_html(input_file):
    """Parse the Prowler HTML report into a DataFrame."""
    html_content = Path(input_file).read_text(encoding="utf-8")
    soup = BeautifulSoup(html_content, "html.parser")

    findings_table = soup.find("table", id="findingsTable")
    if not findings_table:
        raise ValueError("Could not find the main findings table (id='findingsTable') in the HTML.")

    tbody = findings_table.find("tbody")
    if not tbody:
        raise ValueError("Could not find the findings table body in the HTML.")

    findings = []
    for row in tbody.find_all("tr"):
        cells = row.find_all("td")
        if len(cells) < 11:
            continue

        row_data = []
        for index in HTML_COLUMNS_TO_EXTRACT:
            row_data.append(clean_text(cells[index].decode_contents()))
        findings.append(row_data)

    return pd.DataFrame(findings, columns=CSV_HEADER)


def normalize_column_name(name):
    return "".join(ch.lower() for ch in str(name).strip() if ch.isalnum())


def resolve_column(df, candidates):
    normalized = {normalize_column_name(col): col for col in df.columns}
    for candidate in candidates:
        resolved = normalized.get(normalize_column_name(candidate))
        if resolved:
            return resolved
    return None


def build_docx(input_df, output_docx, severity):
    df = input_df.copy()
    df.columns = [c.strip() for c in df.columns]

    col_map = {
        "Severity": ["Severity"],
        "Status": ["Status"],
        "Check Title": ["Check Title", "Title", "CheckTitle"],
        "Status Extended": ["Status Extended", "StatusExtended", "Description"],
        "Risk": ["Risk"],
        "Resource ID": [
            "Resource ID",
            "ResourceID",
            "Affected Resource IDs",
            "resource_id",
        ],
        "Recommendation": ["Recommendation", "Recommendations"],
    }

    resolved = {}
    for key, names in col_map.items():
        found = resolve_column(df, names)
        if not found:
            raise ValueError(f"Missing required column for {key}")
        resolved[key] = found

    df_filtered = df[
        (df[resolved["Status"]].astype(str).str.lower() == "fail")
        & (df[resolved["Severity"]].astype(str).str.lower() == severity.lower())
    ]

    doc = Document()
    doc.add_heading(f"{severity.title()} Findings", level=1)

    if df_filtered.empty:
        doc.add_paragraph(f"No FAIL findings found for severity: {severity.upper()}.")
        doc.save(output_docx)
        return 0

    grouped = df_filtered.groupby(resolved["Check Title"], dropna=False)

    for check_title, group in grouped:
        doc.add_heading(str(check_title), level=3)

        def add_unique_bullets(title, column):
            doc.add_heading(title, level=4)
            unique_values = group[column].dropna().astype(str).unique()
            if len(unique_values) == 0:
                doc.add_paragraph("No data found.", style="List Bullet")
                return
            for val in unique_values:
                doc.add_paragraph(val, style="List Bullet")

        add_unique_bullets("Description", resolved["Status Extended"])
        add_unique_bullets("Risk", resolved["Risk"])
        add_unique_bullets("Affected Resource IDs", resolved["Resource ID"])
        add_unique_bullets("Recommendations", resolved["Recommendation"])
        doc.add_paragraph("")

    doc.save(output_docx)
    return len(df_filtered)


def main():
    parser = argparse.ArgumentParser(
        description="Parse a Prowler HTML report and generate severity-based DOCX reports."
    )
    parser.add_argument("-f", "--file", required=True, help="Input Prowler HTML file")
    parser.add_argument("-o", "--output", required=True, help="Output directory for DOCX files")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    df = parse_prowler_html(args.file)

    severities = ["critical", "high", "medium", "low"]
    for severity in severities:
        output_docx = output_dir / f"{severity}.docx"
        count = build_docx(df, output_docx, severity)
        print(f"[+] Generated {output_docx} ({count} FAIL findings)")


if __name__ == "__main__":
    main()

# Prowler Report Toolkit

A set of Python scripts for post-processing [Prowler](https://github.com/prowler-cloud/prowler) HTML scan reports into more shareable formats: CSV, an Excel summary by service/region, and severity-grouped Word documents containing only the FAIL findings.

## Scripts

| Script | Input | Output | Purpose |
| --- | --- | --- | --- |
| `html2csv.py` | Prowler HTML report | `output.csv` | Extract findings into a cleaned CSV. |
| `calc-finding.py` | CSV from `html2csv.py` | `prowler_report.xlsx` | Aggregate findings by service, region, and FAIL counts across service x region. |
| `script.py` | Prowler HTML report | `critical.docx`, `high.docx`, `medium.docx`, `low.docx` | Generate one DOCX per severity, grouped by check, containing FAIL findings only. |

## Requirements

```bash
python3 -m pip install pandas beautifulsoup4 python-docx openpyxl
```

## Usage

### 1. HTML to CSV

```bash
python3 html2csv.py <input.html> -o output.csv
```

Extracts the `findingsTable` rows and writes the columns: `Status`, `Severity`, `Service Name`, `Region`, `Check Title`, `Resource ID`, `Status Extended`, `Risk`, `Recommendation`.

### 2. CSV to Excel summary

```bash
python3 calc-finding.py -f output.csv -o prowler_report.xlsx
```

Produces a workbook with three sheets:

- **By Service** - status counts per service, sorted by FAIL.
- **By Region** - status counts per region, sorted by FAIL.
- **FAIL Service x Region** - pivot of FAIL findings across service and region.

### 3. HTML to DOCX (per severity)

```bash
python3 script.py -f <input.html> -o results/
```

Creates the output directory if needed and writes:

- `results/critical.docx`
- `results/high.docx`
- `results/medium.docx`
- `results/low.docx`

Each document groups FAIL findings by check title with description, risk, affected resources, and recommendation.

## Notes

- All HTML parsing expects the Prowler findings table at `id="findingsTable"`.
- Only findings with `Status = FAIL` are included in the DOCX output.
- `script.py` reads the HTML directly, so the CSV step is not required to produce the DOCX reports.

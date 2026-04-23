# Prowler Report Converter

This project converts a Prowler HTML report into four Word documents, one for each severity level:

- `critical.docx`
- `high.docx`
- `medium.docx`
- `low.docx`

The combined script reads the HTML report directly, so you do not need to run the old CSV export and CSV-to-DOCX steps separately.

## Requirements

Install the Python packages used by the script:

```bash
python3 -m pip install pandas beautifulsoup4 python-docx
```

## Usage

1. Download the Prowler report from the scan job.
2. Run the script against the HTML file:

```bash
python3 script.py -f <input.html> -o results/
```

Example:

```bash
python3 script.py -f <redacted-report.html> -o results/
```

## Output

The command creates the output directory if it does not already exist and writes these files inside it:

- `results/critical.docx`
- `results/high.docx`
- `results/medium.docx`
- `results/low.docx`

Each document contains grouped FAIL findings for that severity.

## Notes

- The script expects the Prowler HTML report to contain the findings table with `id="findingsTable"`.
- Only findings with `Status = FAIL` are included in the DOCX output.

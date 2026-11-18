# Prowler Report Toolkit

Turns a [Prowler](https://github.com/prowler-cloud/prowler) AWS scan into a preliminary cloud penetration test report, ready for review.

## Files

| File            | Purpose                                                      |
| --------------- | ------------------------------------------------------------ |
| `final.py`      | Generates the report and the Excel files.                    |
| `template.docx` | Report template: cover, disclaimer, sections, charts and appendices. Keep it next to `final.py`. |

## Requirements

- Python 3.9+
- Packages:

```bash
python3 -m pip install pandas openpyxl beautifulsoup4 python-docx lxml boto3
```

- AWS credentials for the scanned account (the same ones used for the Prowler scan), so the script can read the caller identity. `boto3` is optional. Without it or without valid credentials, see [AWS caller identity](#aws-caller-identity).

## Input

Put the Prowler output for one scan in a folder:

```
raw-report/
├── prowler-output-<account>-<timestamp>.csv    # required for remediation code
└── prowler-output-<account>-<timestamp>.html   # optional
```

Use the **CSV**. It is the only Prowler output that includes the Remediation Steps, CLI, Terraform and CloudFormation code. The HTML is used only when no CSV exists for a scan, and the report then has no remediation code.

## Usage

```bash
python3 final.py -f <input-folder> -o <output-folder> [options]
```

**Scan and report on the same day** (uses the default AWS credentials for the caller identity):

```bash
python3 final.py -f raw-report/ -o out-report/ --project "EM Cloud"
```

**Assessment over several days:**

```bash
python3 final.py -f raw-report/ -o out-report/ \
  --project "Yoma Elevator" \
  --start "01 June 2026" --end "04 June 2026" --date "05 June 2026" \
  --profile pt-ro-temp
```

**Report built on another machine than the scan** (no AWS access):

```bash
python3 final.py -f raw-report/ -o out-report/ --project "EM Cloud" --no-aws \
  --user-id "AIDAXXXXXXXXXXXXXXM6V" \
  --caller-arn "arn:aws:iam::470000000059:user/pt-ro-temp"
```

### AWS caller identity

The **AWS User ID** and **Caller Identity ARN** rows in the Scope table are filled in from `aws sts get-caller-identity`. The script reads them from the current AWS credentials, or from the profile given with `--profile`. This call needs no IAM permissions.

Both values are redacted before they go into the report:

| Value                 | From                                           | In the report                                |
| --------------------- | ---------------------------------------------- | -------------------------------------------- |
| User ID               | `AIDAXXXXXXXXXXXXXXM6V`                        | `AI****M6V`                                  |
| User ID (assumed role) | `AROAXXXXXXXXXXXXXXQ7Z:pt-session`            | `AR****Q7Z:pt-session`                       |
| Caller Identity ARN   | `arn:aws:iam::470000000059:user/pt-ro-temp`    | `arn:aws:iam::47********59:user/pt-ro-temp`  |

- `--user-id` and `--caller-arn` override the AWS lookup. Pass the real values; they are redacted the same way. Values that already contain `*` are used as they are.
- `--no-aws` skips the AWS call.
- If the lookup fails (no `boto3`, no or expired credentials), the script prints a warning and the report shows `[AWS User ID]` and `arn:aws:iam::<masked account>:user/[user]`. Fix these by hand or run again with `--profile` / `--user-id` / `--caller-arn`.
- If the current credentials belong to a different account than the scanned one, the script prints a warning. Check that you used the right profile.

### Options

| Option             | Description                                                  | Default                                     |
| ------------------ | ------------------------------------------------------------ | ------------------------------------------- |
| `-f`, `--folder`   | Folder with the Prowler output, or a single `.csv` / `.html` file | required                                    |
| `-o`, `--output`   | Output folder (created if missing)                           | required                                    |
| `--project`        | Project name, used on the cover, in the text and in file names | `[Project Name]`                            |
| `--client`         | Client shown under "Prepared for"                            | `Yoma Strategic Holdings Ltd.`              |
| `--code`           | Client code shown in the header and footer                   | `YSH01`                                     |
| `--start`          | Assessment start date                                        | same as end date                            |
| `--end`            | Assessment end date                                          | scan date from the CSV                      |
| `--date`           | Report date (cover and revision history)                     | today                                       |
| `--profile`        | AWS CLI profile used to read the caller identity             | default AWS credentials                     |
| `--user-id`        | AWS user ID used for the scan (Scope table). Redacted in the report | from `sts get-caller-identity`       |
| `--caller-arn`     | Caller identity ARN used for the scan (Scope table). Account ID redacted | from `sts get-caller-identity`  |
| `--no-aws`         | Do not call AWS; use `--user-id` / `--caller-arn` or placeholders | off                                    |
| `-t`, `--template` | Use a different report template                              | `template.docx`                             |

Write dates as `DD Month YYYY`, for example `01 June 2026`. When the start and end dates are the same, the report says "on 01 June 2026" instead of "from … to …".

## Output

```
out-report/
├── rpt.ysh-em-cloud-pentest-prelim.20261013.docx   # preliminary report
├── rpt.ysh-em-cloud-pentest-prelim.20261013.xlsx   # findings
└── finding-count.xlsx                              # finding counts
```

File names follow `rpt.<code>-<project>-cloud-pentest-prelim.<YYYYMMDD>`. The date is the report date.

### Preliminary report (`.docx`)

Built from `template.docx`. These parts are filled in automatically:

- **Cover, header and footer:** project, client, client code and report date.
- **Executive Summary:** assessment dates, the number of critical and high-risk findings, and the most affected services.
- **Scope:** masked AWS account ID, AWS user ID and Caller Identity ARN (see [AWS caller identity](#aws-caller-identity)).
- **Findings:** the finding count per severity, plus three charts: findings by severity, FAIL count by AWS service and FAIL count by AWS region.
- **Findings by severity (Critical, High, Medium, Low):** one heading per failed Prowler check, with:
  - Description
  - Risk
  - Affected Resource IDs
  - Recommendations
  - Remediation Steps (when Prowler provides them)
  - CLI, Terraform and CloudFormation code (when Prowler provides it)
- **Appendix C:** the Prowler version.

A finding is one failed Prowler check. All affected resources for that check are listed under it.

### Findings (`.xlsx`)

One row per Prowler result (FAIL, PASS and MANUAL). FAIL rows come first, sorted by severity and then check title. Columns: Status, Severity, Service Name, Region, Check Title, Resource ID, Status Extended, Risk, Recommendation, Reference URL, Remediation Steps, CLI, Terraform, CloudFormation.

### Finding counts (`finding-count.xlsx`)

| Sheet                 | Contents                                     |
| --------------------- | -------------------------------------------- |
| FAIL By Severity      | Findings and affected resources per severity |
| By Service            | PASS / FAIL / MANUAL counts per service      |
| By Region             | PASS / FAIL / MANUAL counts per region       |
| FAIL Service x Region | FAIL counts per service and region           |

## Before sending the report

1. Open the `.docx` in Word and click **Yes** when asked to update fields. This refreshes the table of contents, page numbers and figure/table lists.
2. Fill in the client project team (Table A.2).
3. Check the AWS User ID and Caller Identity ARN in the Scope table. They must be the identity used for the scan, not placeholders.
4. Check the tool versions in Appendix C.
5. Review the Executive Summary text. It is generated from the scan data.

## Notes

- Only FAIL results appear in the report. PASS and MANUAL results are in the findings `.xlsx`.
- Findings with a severity other than Critical, High, Medium or Low (for example informational) are not in the report. The script prints a warning if any exist.
- If the input folder holds several scans, each one gets its own subfolder in the output folder.
- To change the report's fixed text, edit `template.docx` and keep the `{{PLACEHOLDER}}` fields and the `{{FINDINGS}}` line in place.

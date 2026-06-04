import argparse
import csv
from bs4 import BeautifulSoup
import re
import os

def clean_text(text):
    """
    Cleans up extracted text by removing HTML artifacts, Prowler's specific tags,
    and normalizing whitespace.
    """
    # 1. Remove optional break tags from Prowler output
    text = text.replace('<wbr />', '')
    
    # 2. Use BeautifulSoup to parse and get clean text, which handles embedded 
    # tags like <p>, <b>, and HTML entities (like bullet points).
    soup = BeautifulSoup(text, 'html.parser')
    
    # Use get_text() with a space separator to ensure words don't run together
    text = soup.get_text(separator=' ', strip=True)
    
    # 3. Normalize whitespace: replace multiple spaces, newlines, and tabs with a single space
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text

def parse_prowler_html(input_file, output_file):
    """
    Parses the Prowler HTML report and saves the findings to a CSV file.
    """
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            html_content = f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        return
    except Exception as e:
        print(f"Error reading input file: {e}")
        return

    soup = BeautifulSoup(html_content, 'html.parser')
    
    # The main findings table is identified by id='findingsTable'
    findings_table = soup.find('table', id='findingsTable')
    
    if not findings_table:
        print("Error: Could not find the main findings table (id='findingsTable') in the HTML.")
        return

    # Define the desired columns and their 0-based index in the HTML table
    # The full table columns are:
    # 0: Status, 1: Severity, 2: Service Name, 3: Region, 4: Check ID (Skip)
    # 5: Check Title, 6: Resource ID, 7: Resource Tags (Skip), 8: Status Extended
    # 9: Risk, 10: Recommendation, 11: Compliance (Skip)
    
    COLUMNS_TO_EXTRACT = [0, 1, 2, 3, 5, 6, 8, 9, 10]
    
    # Define the header for the CSV file in the requested order
    csv_header = [
        'Status', 'Severity', 'Service Name', 'Region', 'Check Title', 
        'Resource ID', 'Status Extended', 'Risk', 'Recommendation'
    ]

    findings = []
    
    # Iterate over all table rows in the tbody (excluding the header)
    rows = findings_table.find('tbody').find_all('tr')
    
    for row in rows:
        cells = row.find_all('td')
        
        # Skip rows that don't have the expected number of columns
        if len(cells) < 11:
            continue
            
        row_data = []
        for index in COLUMNS_TO_EXTRACT:
            cell = cells[index]
            # Get the content's inner HTML/text for cleaning
            raw_content = cell.decode_contents()
            
            # Clean and append the text
            cleaned_text = clean_text(raw_content)
            row_data.append(cleaned_text)
            
        findings.append(row_data)

    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(csv_header)
            writer.writerows(findings)
        
        print(f"Successfully extracted {len(findings)} findings to {output_file}.")

    except Exception as e:
        print(f"Error writing to CSV file: {e}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Extract Prowler HTML findings to CSV.")
    # The script now takes the input HTML file as a positional argument
    parser.add_argument('input_file', help="The path to the input Prowler HTML file.")
    # The output CSV file is taken via the -o argument
    parser.add_argument('-o', '--output', required=True, help="The path for the output CSV file.")

    args = parser.parse_args()
    parse_prowler_html(args.input_file, args.output)

import os.path
import base64
import re
from datetime import datetime
from bs4 import BeautifulSoup
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import gspread

# Scopes for accessing Gmail and Google Sheets with read and write permissions
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/spreadsheets'
]
CREDENTIALS_FILE = 'credentials.json'
TOKEN_FILE = 'token.json'

# The ID of the Google Sheet we are working with.
SAMPLE_SPREADSHEET_ID = "19MBKw6EtDxDbbK7V08NeakBIC1QESO9XysAHJw6xu1o"  # Replace with your own sheet ID

def authenticate():
    creds = None
    # Load credentials from file if they exist
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    # If there are no (valid) credentials available, prompt the user to log in
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())

    return creds


def save_emails_to_google_sheet(email_data, creds):
    try:
        # Authorize Google Sheets API using the credentials
        client = gspread.authorize(creds)

        # Open the Google Sheet by its ID
        sheet = client.open_by_key(SAMPLE_SPREADSHEET_ID).sheet1

        # Retrieve all existing values to check for headers and already stored emails
        existing_values = sheet.get_all_values()
        headers = ['Message ID', 'Date', 'Time', 'To', 'From', 'Body']

        # Check if the first row contains the correct headers; if not, insert the headers
        if not existing_values or existing_values[0] != headers:
            if not existing_values:
                sheet.insert_row(headers, 1)
            elif existing_values[0] != headers:
                sheet.update('A1:F1', [headers])  # Update header in place

        # Extract the list of already stored message IDs to avoid redundancy
        stored_message_ids = set()
        if len(existing_values) > 1:
            stored_message_ids = {row[0] for row in existing_values[1:]}

        # Collect only new email data into rows
        rows = []
        for data in email_data:
            # Check if this email's ID is already in the sheet
            if data['message_id'] not in stored_message_ids:
                # Split the email body into chunks of 50,000 characters
                chunks = [data['body'][i:i + 50000] for i in range(0, len(data['body']), 50000)]

                # Start creating the row to insert (include the message ID)
                row = [data['message_id'], data['date'], data['time'], data['to'], data['from']] + chunks
                rows.append(row)

        # Append all new rows to the sheet in a batch operation
        if rows:
            sheet.append_rows(rows, value_input_option="RAW")
            print(f"Number of rows added: {len(rows)}")
        else:
            print("No new rows were added.")

    except Exception as e:
        print(f'An error occurred while saving to Google Sheets: {e}')


def extract_parts(parts, email_body):
    """Recursively extract parts of the email."""
    for part in parts:
        if part['mimeType'] == 'text/plain' or part['mimeType'] == 'text/html':
            data = part['body'].get('data')
            if data:
                text = base64.urlsafe_b64decode(data).decode('utf-8')
                email_body += text + " "
        elif 'parts' in part:
            email_body = extract_parts(part['parts'], email_body)
    return email_body


def get_full_email_content(service, user_id, msg_id):
    try:
        message = service.users().messages().get(userId=user_id, id=msg_id, format='full').execute()
        payload = message['payload']
        headers = payload.get('headers', [])
        email_body = ""

        email_data = {
            'message_id': msg_id,  # Add the message ID for tracking
            'date': '',
            'time': '',
            'to': '',
            'from': '',
            'body': ''
        }

        for header in headers:
            if header['name'].lower() == 'date':
                raw_date = header['value']
                try:
                    parsed_date = datetime.strptime(raw_date[:25], '%a, %d %b %Y %H:%M:%S')
                    email_data['date'] = parsed_date.strftime('%Y-%m-%d')
                    email_data['time'] = parsed_date.strftime('%H:%M:%S')
                except ValueError:
                    email_data['date'] = raw_date
            elif header['name'].lower() == 'to':
                email_data['to'] = header['value']
            elif header['name'].lower() == 'from':
                email_data['from'] = header['value']

        if 'parts' in payload:
            email_body = extract_parts(payload['parts'], email_body)
        elif payload.get('body') and payload['body'].get('data'):
            email_body = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8')

        email_body = extract_current_message(email_body)
        email_body = email_body.replace('\n', ' ').replace('\r', ' ').strip()
        email_data['body'] = email_body

        return email_data

    except Exception as e:
        print(f'An error occurred: {e}')
        return None


def extract_current_message(email_body):
    soup = BeautifulSoup(email_body, 'html.parser')
    for blockquote in soup.find_all('blockquote'):
        blockquote.decompose()
    for div in soup.find_all('div', class_="gmail_quote"):
        div.decompose()
    cleaned_text = soup.get_text()
    reply_pattern = re.compile(r'(On\s+\w{3},\s+\d{1,2}\s+\w{3}\s+\d{4}\s+.*?wrote:)', re.IGNORECASE)
    split_body = reply_pattern.split(cleaned_text)
    if len(split_body) > 1:
        return split_body[0].strip()
    else:
        return cleaned_text.strip()


def search_emails(service, user_id, query, creds):
    try:
        result = service.users().messages().list(userId=user_id, q=query).execute()
        messages = []
        email_data_list = []

        if 'messages' in result:
            messages.extend(result['messages'])
        
        for message in messages:
            email_data = get_full_email_content(service, user_id, message['id'])
            if email_data:
                email_data_list.append(email_data)
                print(f"Retrieved email from: {email_data['from']}, date: {email_data['date']}\n")

        save_emails_to_google_sheet(email_data_list, creds)

    except Exception as e:
        print(f'An error occurred: {e}')


def main():
    # Authenticate and get credentials
    creds = authenticate()

    # Authenticate Gmail
    service = build('gmail', 'v1', credentials=creds)
    user_id = 'me'
    group_email = 'pdedr@nxfin.in'
    query = f"to:{group_email} OR from:{group_email}"

    # Search and save emails
    search_emails(service, user_id, query, creds)

    # Optionally, get some data from the Google Sheet
    # get_google_sheet_data(creds)


if __name__ == '__main__':
    main()

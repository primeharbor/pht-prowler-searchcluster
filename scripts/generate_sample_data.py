from datetime import datetime, timedelta
import json
import os
import random
import uuid

# Define new account IDs and regions
new_account_ids = {"058264364001": "123456789121", "851725201516": "123456789122", "905418163741": "123456789123"}
regions = ["us-west-1", "us-west-2", "us-east-1", "eu-central-1", "ap-southeast-1"]

def replace_file_name(file_name: str):
    parts = file_name.split("-")
    old_account_id = parts[1]

    # Replace the old account ID with the new one using the mapping
    parts[1] = new_account_ids[old_account_id]
    new_filename = "-".join(parts)

    return new_filename

# Function to generate new fake record
def generate_fake_record(record):
    # Clone the record
    new_record = json.loads(json.dumps(record))
    
    new_account_id = new_account_ids[new_record["cloud"]["account"]["uid"]]
    # Modify the account ID
    new_record["cloud"]["account"]["uid"] = new_account_id
    new_record["cloud"]["account"]["name"] = f"fake-account-{new_account_id[-3:]}"
    
    # Modify the event time and created time
    random_days = random.randint(1, 90)
    new_time = datetime.utcnow() - timedelta(days=random_days)
    new_record["event_time"] = new_time.isoformat()
    new_record["finding_info"]["created_time"] = new_time.isoformat()

    # Modify the UID to include new account ID and region
    new_region = random.choice(regions)
    new_record["finding_info"]["uid"] = f"prowler-aws-{new_record['metadata']['event_code']}-{new_account_id}-{new_region}-{uuid.uuid4()}"

    # Modify other fields as necessary
    new_record["resources"][0]["name"] = new_account_id
    new_record["resources"][0]["uid"] = f"arn:aws:iam::{new_account_id}:root"
    new_record["resources"][0]["region"] = new_region
    new_record["cloud"]["region"] = new_region
    
    return new_record

def process_file(file_name: str):
    # Load existing data from a file
    print(f"processing {file_name}")
    with open(file_name, "r") as file:
        data = json.load(file)

    # Generate new records to increase file size
    new_data = []
    for _ in range(100):  # Adjust the range to increase the size of the file
        for record in data:
            new_record = generate_fake_record(record)
            new_data.append(new_record)

    new_file_name = replace_file_name(file_name)
    # Save the new data to a new file
    with open(new_file_name, "w") as file:
        json.dump(new_data, file, indent=4)

    print(f"New data generated and saved as {new_file_name}")

def main():
    json_files = [pos_json for pos_json in os.listdir() if pos_json.endswith('.json')]
    for file in json_files:
        process_file(file)

if __name__ == "__main__":
    main()
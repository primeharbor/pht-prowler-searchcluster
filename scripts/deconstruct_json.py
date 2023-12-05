#!/usr/bin/env python3
# Copyright 2023 Chris Farris <chris@primeharbor.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import sys

ndjson_file = sys.argv[1]

def ndjson_to_json(ndjson_file):
    json_array = []
    with open(ndjson_file, 'r') as file:
        for line in file:
            data = json.loads(line)
            expand_escaped_json(data)
            json_array.append(data)
    return json_array

def expand_escaped_json(data):
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, str):
                try:
                    unescaped_value = json.loads(value)
                    data[key] = unescaped_value
                except json.JSONDecodeError:
                    pass
            else:
                expand_escaped_json(value)
    elif isinstance(data, list):
        for i in range(len(data)):
            if isinstance(data[i], str):
                try:
                    unescaped_value = json.loads(data[i])
                    data[i] = unescaped_value
                except json.JSONDecodeError:
                    pass
            else:
                expand_escaped_json(data[i])



# Convert NDJSON to JSON object array
result = ndjson_to_json(ndjson_file)

# Convert the result to a JSON string
json_string = json.dumps(result, indent=2)

# Print the JSON string
print(json_string)

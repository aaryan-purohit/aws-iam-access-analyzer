import re

pattern = r"\w+:\*"
action = "ec2:*"

if re.match(pattern, action):
    print("Match found!")
else:
    print("No match.")
 
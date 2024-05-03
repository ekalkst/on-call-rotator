# on-call-rotator

This script will rotate the user of a slack group id for an on call rotation, using the schedule from Pagerduty.  
Two environment variables/secrets will need to be set. One for the Pagerduty API token, and the other for the slack API (using a slack bot token)

Example usage

```python oncallrotation.py -s scheduleABC -r groupid123```

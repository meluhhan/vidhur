# Vidhur Engagement Policy

Edit the JSON below for one authorized assessment. Host commands run with your user permissions and network access; Vidhur does not provide an OS sandbox. Keep execution disabled unless you trust the target and explicitly authorize its scope.

```json
{
  "version": 2,
  "target": "",
  "revision": "unspecified",
  "goal": "",
  "crown_jewels": [],
  "authorization": {
    "authorized": false
  },
  "scope": {
    "in_scope": [],
    "out_of_scope": [".env", "**/.env", "**/*secret*", "**/*credential*"]
  },
  "execution": {
    "allow_host_execution": false,
    "allow_package_installation": false
  },
  "forbidden_actions": [
    "network access",
    "destructive changes",
    "accessing out-of-scope paths",
    "submitting or transmitting target data"
  ],
  "adversarial_oracles": [
    {
      "name": "reject_oversize_header",
      "rejection_pattern": "HTTP/1\\.1 4\\d\\d|request rejected|header too large",
      "description": "Server must reject the exact payload that previously overflowed the parser."
    },
    {
      "name": "reject_sql_metacharacters",
      "rejection_pattern": "invalid input|query rejected|syntax error near",
      "description": "Endpoint must explicitly reject the SQL metacharacter payload."
    }
  ],
  "budget": {
    "max_commands": 0,
    "command_timeout_seconds": 60,
    "total_runtime_seconds": 0
  }
}
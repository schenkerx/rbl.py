# rbl.py

rbl.py is a handy tool to check your email server's IP reputation and setting correctness. It utilize major DNSBL services and other mechanisms to achieve this goal.

## Usage

| Command Line Option | Description                              |
| ------------------- | ---------------------------------------- |
| `-h` or `--help`    | Show help message and exit               |
| `-a` or `--ip`      | IP address to check (default: your public IP address). You can use multiple `-a` options to run check for multiple IPs. |
| `-t` or `--timeout` | Time before query timeout (default: 5 seconds). |


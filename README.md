# Introduction

Here I will share some scripts I made for Infoblox DDI and BloxOne

<pre>
usage: ibx.py [-h] [-v] --url API_URL --user API_USER --pass API_PASS [--test] [-1] [--logfile LOGFILE] [--debug]

Infoblox Scripts by Stefan Braitti

options:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit

API Connection:
  --url API_URL, -U API_URL
                        URI for the Infoblox API
  --user API_USER, -u API_USER
                        Username for the Infoblox API
  --pass API_PASS, -p API_PASS
                        Password for the Infoblox API
  --test                Test the connection with Infoblox API

Unmanaged to Managed:
  -1                    Activate script Unmanaged to Managed

Log Options:
  --logfile LOGFILE     Log file name (Default: logfile.log)
  --debug               Log debug
</pre>
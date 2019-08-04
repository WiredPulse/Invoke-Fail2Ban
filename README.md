# PowerShell version of Fail2Ban
This script monitors a Windows system for attempted brute force authentications. After the defined number of failures have occured, the script will create a firewall rule to block the IP for a defined period of time. Additionally, when an IP is banned, the event is written to the system's event log under and stored in a queryable SQL DB. The IP(s) of the system that is running the script are automatically whitelisted with the ability to add additional IPs to the whitelist.
<br>
<br>

# Usage <br>
1. Download repo and unzip repo
2. Edit script with your favorite text editor and adjust configs just after initial comment, as desired
3. Save scrip  and execute it
4. Follow the options (see screenshots below)
<br>

# Configurable options <br>
* Configurable threshold of failed login attempts and how long an IP should be blocked<br>
* IP whitelisting<br>
* Logging blocked IPs to Windows event log with customizable event source and ID<br>
* Logging blocked and whitelisted IPs to a queryable SQL database<br>
* Customizable ban timeout<br>
* Option for mass and quick removal of all banned IPs before a ban expiration occurs<br>
<br>
<br>

# Screenshots <br>
<br>

Running the script<br>
![Alt text](https://github.com/WiredPulse/Invoke-Fail2Ban/blob/master/Images/1-Menu.png?raw=true "Optional Title")<br>
<br>

Configuring the Whitelist<br>
![Alt text](https://github.com/WiredPulse/Invoke-Fail2Ban/blob/master/Images/2-Configure_whitelist.png?raw=true "Optional Title")<br>
<br>

Monitoring and banning<br>
![Alt text](https://github.com/WiredPulse/Invoke-Fail2Ban/blob/master/Images/3-Output.png?raw=true "Optional Title")<br>
<br>

Banned IP in Event Log<br>
![Alt text](https://github.com/WiredPulse/Invoke-Fail2Ban/blob/master/Images/4-Evt_log.png?raw=true "Optional Title")<br>
<br>

Banned IP firewall rule(begins with "ban")
![Alt text](https://github.com/WiredPulse/Invoke-Fail2Ban/blob/master/Images/5-FW.png?raw=true "Optional Title")<br>
<br>

Retrieving banned IPs through the script
![Alt text](https://github.com/WiredPulse/Invoke-Fail2Ban/blob/master/Images/6-Ban_IP.png?raw=true "Optional Title")<br>
<br>

Retrieving banned IPs within the SQL DB 
![Alt text](https://github.com/WiredPulse/Invoke-Fail2Ban/blob/master/Images/7-Query_DB.png?raw=true "Optional Title")<br>
<br>

Removing all banned IPs before their expiration
![Alt text](https://github.com/WiredPulse/Invoke-Fail2Ban/blob/master/Images/8-Remove_rules.png?raw=true "Optional Title")<br>
<br>

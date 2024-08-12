# Suricata Installation with Emerging Threats (ET) Ruleset, Wazuh Integration, and Nmap Testing on Ubuntu Server

## Overview

This project provides a comprehensive guide to installing Suricata, an
open-source network threat detection engine, on an Ubuntu Server. It
includes configuring Suricata with the Emerging Threats (ET) ruleset,
integrating it with the Wazuh agent for centralized security monitoring,
and testing the setup using Nmap to simulate network scanning probe
attacks.

## Prerequisites

Before you start, ensure the following:

- Ubuntu Server 20.04 LTS or later: This guide assumes you are using
  Ubuntu 20.04, though it should be similar for other versions.

- Root or sudo privileges: Administrative access is necessary to install
  packages and modify configurations.

- Basic Linux command-line knowledge: Understanding basic commands and
  system administration is required.

## Lab Setup

In this lab setup, we need three parts: an attacker machine (Kali Linux
or Ubuntu), an Ubuntu machine or Windows machine with the Wazuh agent
installed on it, and finally, our Wazuh server. If you use a Kali Linux
machine, Nmap is preinstalled; however, if you use an Ubuntu machine,
you can install the Nmap package using the sudo apt-get install nmap
command.

**Network Diagram of the Lab Setup**

![image1](https://github.com/user-attachments/assets/c01d4042-e1de-4b90-819c-2112c8374e73)


## Installation Steps

### Update Your System

**Ubuntu IP address and Interface**

![image2](https://github.com/user-attachments/assets/06b016ae-a6a8-4115-a524-80484a211085)



Ensure your package list is up to date:

  - sudo apt update

  - sudo apt install -y



- **Screenshot**: **Terminal showing system update commands and output**

![image3](https://github.com/user-attachments/assets/b621d591-c92d-493f-8fc0-cc3d484aaa96)

![image4](https://github.com/user-attachments/assets/87457f4a-0343-401e-9307-1888068952fb)


### Install Dependencies

Suricata requires several dependencies. Install them with:

- sudo apt install -y software-properties-common apt-transport-https
lsb-release ca-certificates curl jq

- **Terminal showing dependencies installation**

![image5](https://github.com/user-attachments/assets/15ac11c0-8ce0-4f50-8deb-46cbbbb12290)


### Add the Suricata PPA

Add the official Suricata PPA to get the latest stable version:

- sudo add-apt-repository ppa:oisf/suricata-stable

- sudo apt update

- **Terminal showing the addition of the Suricata PPA and the update
  command**

![image](https://github.com/user-attachments/assets/7e151f2c-f04e-4c03-8c3b-92e4591f0346)

![image](https://github.com/user-attachments/assets/55b76058-ee2b-4dc4-99de-1fdd833b717b)

### Install Suricata

Install Suricata using the following command:

- sudo apt install -y suricata

- **Terminal showing the Suricata installation**

![image](https://github.com/user-attachments/assets/4c7642bd-3098-4602-86ed-d423c4758cbc)

### Download and Install the Emerging Threats (ET) Ruleset

The Emerging Threats (ET) ruleset can be installed directly from the
Suricata rules directory.

Navigate to the Suricata rules directory:

- cd /etc/suricata/rules

If the directory doesn’t exist, then check the existing Suricata
directory:

- ls -l /etc/suricata

If the rules directory does not exist create the rule directory:

- sudo mkdir /etc/suricata/rules

Download the ET Open ruleset:

- sudo wget
https://rules.emergingthreats.net/open/suricata-5.0/emerging.rules.tar.gz

Extract the rules:

- sudo tar -xvzf emerging.rules.tar.gz

Remove the downloaded tar file:

- sudo rm emerging.rules.tar.gz

- **Terminal showing the download, extraction, and cleanup of the ET
  ruleset**

![image](https://github.com/user-attachments/assets/074bd81a-f5cb-46f8-81bf-80b265911c49)

![image](https://github.com/user-attachments/assets/ea945a3f-f037-4785-abf7-d1e28b0b5376)

![image](https://github.com/user-attachments/assets/ec206525-9f00-4c1a-a1c7-4bbd605d1933)

### Modify the Suricata Configuration

#### Configure the Network Interface and IP Address

Suricata needs to be configured to monitor the specific network
interface and IP address. Modify the /etc/suricata/suricata.yaml file:

Open the configuration file in your preferred text editor:

- sudo nano /etc/suricata/suricata.yaml

Locate the af-packet section and configure it with the interface ens33
and the IP address 192.168.5.1:

![image](https://github.com/user-attachments/assets/5719f14e-4758-415a-b7aa-1ac04ec09e46)


In the vars section, configure the IP address for HOME_NET:
![image](https://github.com/user-attachments/assets/20eda5dd-b7f1-4b09-9cc3-72d30f7e1558)

Save and close the file.

- **The af-packet and vars sections in the suricata.yaml file**

![image](https://github.com/user-attachments/assets/519130a5-95e8-4df3-9429-889cef8bf873)

![image](https://github.com/user-attachments/assets/c40ed9e4-fbd3-4c33-b1ae-7119814168b0)

![image](https://github.com/user-attachments/assets/fd38a426-0f9c-4a3b-a360-b2e36640e1f4)

#### Configure Suricata with ET Rules

In the /etc/suricata/suricata.yaml file, locate the rule-files section
and add the ET rules:
![image](https://github.com/user-attachments/assets/cb028ff0-c0a7-422b-8ee5-a3ab30b8190a)

Ensure to include the directory to the rule

Save and close the file.

- **The rule-files section in the suricata.yaml file**

![image](https://github.com/user-attachments/assets/e59b5ba7-1f4c-4bc4-ad59-8345d8b3879d)

### Test Suricata with the ET Ruleset

To ensure everything is working, test Suricata in pcap processing mode
using a sample .pcap file:

#### Download the Sample .pcap File:

- curl http://testmynids.org/uid/index.html

#### Examine the Logs:

- View real-time alerts using:

- sudo tail -f /var/log/suricata/fast.log

#### Detailed JSON Logs:

For detailed JSON logs, we need to download and install jq to make the
logs readable:

- sudo apt-get update

- sudo apt-get install jq

#### Format and view the JSON log file:

- cat /var/log/suricata/eve.json \| jq .

**Terminal showing the output of the Suricata test with a pcap file**

![image](https://github.com/user-attachments/assets/0dd4dd72-f5fc-4885-887e-6f1b1ed1841a)

**Terminal showing real-time alerts using**

![image](https://github.com/user-attachments/assets/11485f67-e391-47d5-9240-68f066f77bc8)

**Terminal showing detailed JSON Logs**

![image](https://github.com/user-attachments/assets/39b0149f-39ba-420b-959b-ea7ae7e8835e)

### Start and Enable Suricata

To ensure Suricata starts on boot and is currently running with the ET
ruleset and the correct network configuration, use:

- sudo systemctl start suricata

- sudo systemctl enable suricata

- **Terminal showing Suricata being started and enabled**

![image](https://github.com/user-attachments/assets/fb12bfc6-abc0-4141-8c5c-dd39ca519f1e)

### Integrate Suricata with Wazuh Agent

#### Install the Wazuh Agent

Add the Wazuh repository:

- curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \| sudo apt-key add-

- echo "deb https://packages.wazuh.com/4.x/apt/ stable main" \| sudo tee
/etc/apt/sources.list.d/wazuh.list

Install the Wazuh agent:

- sudo apt update

- sudo apt install wazuh-agent -y

Configure the Wazuh agent by editing the configuration file:

- sudo nano /var/ossec/etc/ossec.conf

In the \<client\> section, configure the Wazuh manager's IP address
(replace WAZUH_MANAGER_IP with 192.168.187.136):

![image](https://github.com/user-attachments/assets/de7dc999-c423-4c2e-b3c4-aa0f91c00e24)


Save and close the file.

- **The \<client\> section in the ossec.conf file**

![image](https://github.com/user-attachments/assets/a02a9701-531a-449c-ae76-c17b5c4e6879)

#### Configure Suricata to Send Logs to Wazuh

Open the Configuration File

- sudo nano /etc/suricata/suricata.yaml

Modify the Suricata configuration to output JSON logs to a file:

![image](https://github.com/user-attachments/assets/c851a6b6-a3bc-4b9b-a14c-09cd0cfd80d5)




Configure Wazuh to monitor the Suricata log file by adding the following
to the Wazuh agent configuration:

![image](https://github.com/user-attachments/assets/f19c111f-1ae6-44b0-99b1-f984ae4eda0e)

Save and close the file.

Restart the Wazuh agent:

- sudo systemctl restart wazuh-agent

- **Wazuh agent configuration to monitor the Suricata log file in
  ossec.conf**

![image](https://github.com/user-attachments/assets/487ca08b-7b7b-4567-80c4-5d708b6b23eb)

### Test the System Using Network Scanning Probe Attack (Nmap)

#### Port Scanning with Nmap

Run a basic port scan against a target IP address (in this example,
192.168.1.17):

- nmap -sS -Pn 192.168.1.17

- **Screenshot**: **Nmap port scan results in the terminal**

#### Version Scanning with Nmap

Run a version scan to detect software versions on open ports:

- nmap -sS -sV -Pn 192.168.1.17

- **Nmap version scan results in the terminal**

![image](https://github.com/user-attachments/assets/4b2953b9-e999-4aaa-8bc9-12909d13fc1c)

#### Verify Suricata Detection

After running the Nmap scans, check the Suricata logs to verify that the
scanning activity was detected:

- sudo tail -f /var/log/suricata/fast.log

- **Suricata log (fast.log) showing detection of Nmap activity**

![image](https://github.com/user-attachments/assets/75e18f34-1556-4286-bd28-7d02282b949e)

### Monitor Suricata and Wazuh Logs

Suricata logs can be found in /var/log/suricata/, and Wazuh logs can be
monitored via the Wazuh Dashboard. To view Suricata logs:

- tail -f /var/log/suricata/suricata.log

And for Wazuh:

- sudo tail -f /var/ossec/logs/ossec.log

- **Suricata logs (suricata.log) and Wazuh logs (ossec.log) showing
  detection and alerts**

![image](https://github.com/user-attachments/assets/9643c93f-add1-40ef-9878-a83b1fe7b9f2)

![image](https://github.com/user-attachments/assets/c451118b-52b7-4044-9d1b-d9f77c61247f)

### Visualize on the Wazuh Dashboard

After setting up Suricata and integrating it with the Wazuh agent, you
can visualize the security alerts and logs on the Wazuh Dashboard. The
Wazuh Dashboard provides a centralized interface to monitor and analyse
security events, making it easier to detect and respond to potential
threats.

### Steps to Visualize Suricata Alerts on Wazuh Dashboard

#### Access the Wazuh Dashboard:

- Open a web browser and navigate to the IP address or hostname of your
  Wazuh manager. The URL will typically be in the format:

https://\<WAZUH_MANAGER_IP\>

- Replace \<WAZUH_MANAGER_IP\> with the IP address of your Wazuh manager
  (e.g., 192.168.187.136).

- **The Wazuh login URL.**

![image](https://github.com/user-attachments/assets/870b519b-ba87-4f3a-928a-dbef842194fb)

#### Log in to the Dashboard:

- Enter your username and password default username and password is
  admin to access the Wazuh Dashboard.

- **The login screen with the credentials input fields***.*

![image](https://github.com/user-attachments/assets/ab7f4335-6722-422a-ad5f-c5994c9d8a61)

#### Navigate to the "Security Events" Section:

- Once logged in, click on the "Security Events" or "Security
  Monitoring" tab in the Wazuh Dashboard's main menu. This section
  displays a summary of the security alerts generated by Suricata and
  other sources.

- **A screenshot showing the "Security Events" section with an overview
  of the alerts***.*

![image](https://github.com/user-attachments/assets/db7cbde9-a596-499c-9539-8c7d4e038afc)

#### Filter by Suricata Alerts:

- To focus specifically on Suricata alerts, use the search or filter
  options within the "Security Events" section. You can filter by
  "agent.name" (the name of the server running Suricata) or by specific
  alert types, such as those containing "ET SCAN" in the rule
  description.

- **The filtered view with Suricata-specific alerts highlighted.**

![image](https://github.com/user-attachments/assets/4edead6d-f3fe-44ac-8c6a-a91349defde7)

![image](https://github.com/user-attachments/assets/f129556b-16bd-4e73-ab50-831eaab826ed)

#### Analyse Detailed Alerts:

- Click on an individual alert to view detailed information. This
  includes the timestamp, source and destination IPs, ports, protocol,
  and the specific rule that triggered the alert.

- **The detailed view of a Suricata alert with all relevant information
  visible.**

![image](https://github.com/user-attachments/assets/15448ed6-0152-43e7-aefb-44a482a1b8af)

![image](https://github.com/user-attachments/assets/05bce0dc-bd03-49e8-9bcb-ad62a2232d41)

![image](https://github.com/user-attachments/assets/588cc7b8-12e5-499b-9a7c-3531a6b92427)

### Analysis of Log Results: Suricata Alert for Nmap Scripting Engine

This section provides an in-depth analysis of a specific log entry
generated by Suricata and processed by the Wazuh Manager. The log
highlights an alert triggered by Suricata during the detection of an
Nmap Scripting Engine scan.

#### Overview of the Alert

- **\_index**: wazuh-alerts-4.x-2024.08.11  
  This indicates that the log entry is part of the Wazuh alerts index
  for August 11, 2024.

- **Agent ID**: 003

- **Agent IP**: 192.168.5.1

- **Agent Name**: linux

The log was generated by a Wazuh agent with the ID 003 on a machine with
IP 192.168.5.1, named linux.

#### Alert Details

- **Alert Action**: allowed

The action associated with this alert indicates that the detected
activity was allowed and not blocked by any Intrusion Prevention System
(IPS) rules.

- **Alert Category**: Web Application Attack

This category suggests that the alert pertains to a potential attack
targeting web applications.

- **Signature**: ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap
  Scripting Engine)

- **Signature ID**: 2009358

- **Severity**: 1 (Low)

Suricata identified a scan by detecting the User-Agent associated with
the Nmap Scripting Engine, a popular tool used for network discovery and
security auditing.

#### Network and Protocol Information

- **Source IP**: 192.168.3.2

- **Source Port**: 39908

- **Destination IP**: 192.168.5.1

- **Destination Port**: 8000

- **Protocol**: TCP

- **Application Protocol**: HTTP

The scan originated from IP 192.168.3.2 on port 39908 and targeted IP
192.168.5.1 on port 8000 using the HTTP protocol over TCP.

#### HTTP Request Details

- **HTTP Hostname**: 192.168.5.1

- **HTTP Method**: GET

- **HTTP User-Agent**: Mozilla/5.0 (compatible; Nmap Scripting Engine;
  https://nmap.org/book/nse.html)

- **HTTP Status**: 404

The HTTP request was a GET request targeting the hostname 192.168.5.1,
and it used a User-Agent string associated with the Nmap Scripting
Engine. The server responded with a 404 Not Found status, indicating
that the requested resource (/en-US/HNAP1) was not found.

#### Flow Information

- **Flow ID**: 272142561430655.000000

- **Flow Start Time**: 2024-08-11T14:47:52.980867+0100

The flow data provides details about the bidirectional communication
between the source and destination during the scan. The flow started at
the specified timestamp, and Suricata tracked the number of bytes and
packets exchanged between the client and server.

#### Log Processing Information

- **Log Location**: /var/log/suricata/eve.json

This alert was extracted from the eve.json file, which is Suricata’s
JSON output log file.

- **Input Type**: log

- **Decoder Name**: json

- **Rule ID**: 86601

- **Rule Level**: 3

The log entry was processed using a JSON decoder, and the corresponding
rule (ID: 86601) was triggered. The rule has a level of 3, indicating a
moderate security event.

#### Wazuh Manager Details

- **Manager Name**: wazuh-server

- **Timestamp**: Aug 11, 2024 @ 14:47:54.397

The Wazuh Manager, named wazuh-server, processed this log entry at the
specified timestamp.

## Conclusion

In this project, I successfully installed and configured Suricata with
the Emerging Threats (ET) ruleset, setting it up to monitor a specific
IP address and network interface. Integration with the Wazuh agent
enabled centralized monitoring and detailed logging of security events.
The setup was tested using Nmap to simulate network scanning probe
attacks, which Suricata successfully detected. The logs processed by
Wazuh provided comprehensive details on the detected activities,
confirming the effectiveness of the setup in providing robust network
security monitoring and intrusion detection. For further customization
and advanced configurations, refer to the Suricata and Wazuh
documentation.


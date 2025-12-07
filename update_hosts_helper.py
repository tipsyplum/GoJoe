#!/usr/bin/env python3
import sys

hosts_path = "/etc/hosts"
marker = "#CTF Hosts"
target_hostname = "Target"

def update_hosts(ip):
    try:
        with open(hosts_path, "r") as f:
            lines = f.readlines()

        new_lines = []
        marker_found = False
        updated = False

        i = 0
        while i < len(lines):
            line = lines[i]
            if line.strip() == marker:
                marker_found = True
                new_lines.append(line)

                if i + 1 < len(lines):
                    next_line = lines[i + 1].strip().split()
                    if len(next_line) >= 2 and next_line[1] == target_hostname:
                        new_lines.append(f"{ip}\t{target_hostname}\n")
                        updated = True
                        i += 2
                        continue

                new_lines.append(f"{ip}\t{target_hostname}\n")
                updated = True
                i += 1
                continue

            new_lines.append(line)
            i += 1

        if not marker_found:
            new_lines.append("\n" + marker + "\n")
            new_lines.append(f"{ip}\t{target_hostname}\n")

        with open(hosts_path, "w") as f:
            f.writelines(new_lines)

        print("[+] Hosts file updated.")

    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: update_hosts_helper.py <IP>")
        sys.exit(1)

    update_hosts(sys.argv[1])

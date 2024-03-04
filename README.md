<h2 class="menu-header" id="main">
<a href="https://github.com/Mithlonde/Mithlonde">Root</a>&#xA0;&#xA0;&#xA0;
<a href="https://github.com/Mithlonde/Mithlonde/blob/main/blog/index.md">Blog</a>&#xA0;&#xA0;&#xA0;
<a href="https://github.com/Mithlonde/Mithlonde/blob/main/projects/index.md">Projects</a>&#xA0;&#xA0;&#xA0;
<a href="https://github.com/Mithlonde/Mithlonde/blob/main/projects/index.md">~/Hunter</a>&#xA0;&#xA0;&#xA0;
<a href="https://github.com/Mithlonde/Mithlonde/blob/main/all-writeups.md">Writeups</a>&#xA0;&#xA0;&#xA0;
</h2>

### Hi there 👋

# 👾 Mithlonde
└─$ cat projects/hunter.md

## Hunter
During a penetration test, once you've gained access to the target computer:

- The tool starts by downloading utilities from an external system directly onto the target machine.
- It then performs automated (using the downloaded utilities) as well as manual system reconnaissance to identify security issues.
- All results are written to log files.
- Subsequently, the tool uploads these log files back to the specified external location for analysis.
- Finally, the tool takes care of cleaning up temporary files to erase the trace of activity, including self-destructing of the script itself on the target.

In essence, it eliminates the need for manually typing all commands, downloading, uploading, deleting, etc. This allows me to simply let the tool run while you focus on other tasks, saving a significant amount of time. It also makes the process of report writing way easier due to the color rich logging of commands and output.

**IMPORTANT NOTE**: This tool is still under construction, so updates will be added in the future to make it more streamlined. Currently the linHunter binary only accepts file transfer over HTTP.

linHunter PoC example screenshot:
![2024-02-14_12-58](https://github.com/Mithlonde/Hunter/assets/88001670/7f7cb02f-6035-4db2-85fa-17d2e5aec139)

winHunter PoC example screenshots:
![winHunter-example](https://github.com/Mithlonde/Hunter/assets/88001670/05687cb8-2735-486f-9508-6d206b08c53b)
![winHunter-example-2](https://github.com/Mithlonde/Hunter/assets/88001670/84164fa0-c223-461a-aed6-569b4e4559f1)
![winHunter-example-3](https://github.com/Mithlonde/Hunter/assets/88001670/d538f664-27c1-40c9-b84d-64869e38ccac)

## Usage

```
./linHunter.sh -h                     
Usage: linHunter.sh [OPTIONS]. Skips to manual enumeration if [OPTIONS] are omitted, or only -o is provided

Options:
  -l <ip>        Specify IP to download tools from (requires either -http or -smb)
  -http          Use HTTP method upload for file transfer
  -smb           Use SMB method for file transfer. [!] Note: Currently unavailable
  -o             Write output to linHunter.log (use 'less -r ' to read)
  -tty           Attempt to spawn a TTY shell [!] Note: Currently unavailable
  -c             Done? Clean up downloaded files and logs
  -h             Display this help message

Info: To terminate any background processes started by this script, use the following commands:
  pkill -f "pspy64"    Terminate pspy64 background process
  pkill -f "linpeas"   Terminate linpeas background process
```

Where LinHunter is a fully functional tool including command-line parser options, WinHunter works slightly different while having the same functionalities. With winHunter you can specify the ListeningHost and Method via the script itself:
![image](https://github.com/Mithlonde/Hunter/assets/88001670/b571765e-45f1-47bd-b91e-b0137368d8ee)

```
.\winHunter.ps1 -h
Usage: .\winHunter.ps1 to perform all functions except for '-c'

Options to edit in the script:
  ListeningHost    Specify IP for file transfer
  Method           Specify method for file transfer (smb (default) or http)
  tools            List of tools to download to target
  logsToUpload     List of files to upload to ListeningHost

About Method:
  http             Download function requires: python3 -m http.server 80
                   Upload function requires: python3 -m uploadserver
  smb              Both download and upload functions require: impacket-smbserver share . -smb2support

Additional Command-Line Arguments:
  -c               Done? Clean up downloaded files and logs
  -h               Display this help message
```


- [ ] Debug editor of choice option with the `-e` flag. Note that FileForge is running Visual Studio Code by default. Others will not work sufficiently.
- [ ] Add `--flatten` option to copy all of the files directly into the target directory without creating a new folder.

# Reference-Monitor
A reconfigurable, password-protected reference monitor that prevents write-opens on the files and directories it monitors.

## How to Use
Install the reference monitor from terminal using the commands `make` and then `make install`.
Start the user program to send commands to it by using `make usercode` and then `make run`.
Read the log using `cat ./mountfs/logfile` from the project directory.

## Uninstall
The reference monitor holds a reference to itself to prevent rmmod from working on it. To remove it, send the command `uninstall` from the user program; after that you can unmount the filesystem and remove the module by using `make uninstall` from the terminal

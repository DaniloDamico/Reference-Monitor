# Reference-Monitor
A reconfigurable, password-protected reference monitor that prevents write-opens on the files and directories it monitors.

## How to Use
Install the reference monitor from terminal using the commands `make` and then `make install`.
Start the user program to send commands to it by using `make usercode` and then `make run`.

## Uninstall
After making sure the module is not being locked by the user command `lock`, run `make uninstall` from the terminal

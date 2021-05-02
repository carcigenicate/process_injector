Injects shellcode into a process.

Run as:

    python3 inject.py -n <target process name> -s <path to shellcode>

If there are multiple processes with the same name, is will pick the first one found.

This is more of a PoC than anything. Improving the handling of shellcode and allowing the user to specify by PID are easy improvements that I may make in the future.
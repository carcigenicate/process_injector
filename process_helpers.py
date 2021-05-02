import ctypes as c
import ctypes.wintypes as cw
from typing import Optional, Iterator


TH32CS_SNAPPROCESS = 0x2  # Get snapshot of all processes
MAX_PATH_LENGTH = 255

INVALID_HANDLE_VALUE = -1


kernel32: c.WinDLL = c.windll.kernel32


class PROCESSENTRY32(c.Structure):
    _fields_ = [("dwSize", cw.DWORD),
                ("cntUsage", cw.DWORD),
                ("th32ProcessID", cw.DWORD),
                ("th32DefaultHeapID", cw.PULONG),
                ("th32ModuleID", cw.DWORD),
                ("cntThreads", cw.DWORD),
                ("th32ParentProcessID", cw.DWORD),
                ("pcPriClassBase", cw.LONG),
                ("dwFlags", cw.DWORD),
                ("szExeFile", cw.CHAR * MAX_PATH_LENGTH)]


LPPROCESSENTRY32 = c.POINTER(PROCESSENTRY32)


def typed_f(function_ptr, arg_types, return_type):
    function_ptr.argtypes = arg_types
    function_ptr.restype = return_type
    return function_ptr


create_snapshot = typed_f(kernel32.CreateToolhelp32Snapshot,
                          [cw.DWORD, cw.DWORD],
                          cw.HANDLE)

first_process = typed_f(kernel32.Process32First,
                        [cw.HANDLE, LPPROCESSENTRY32],
                        c.c_bool)

next_process = typed_f(kernel32.Process32Next,
                       [cw.HANDLE, LPPROCESSENTRY32],
                       c.c_bool)

close_handle = typed_f(kernel32.CloseHandle,
                       [cw.HANDLE],
                        c.c_bool)

open_process = typed_f(kernel32.OpenProcess,
                       [cw.DWORD, c.c_bool, cw.DWORD],
                       cw.HANDLE)

remote_virtual_alloc = typed_f(kernel32.VirtualAllocEx,
                               [cw.HANDLE, cw.LPVOID, c.c_size_t, cw.DWORD, cw.DWORD],
                               cw.LPVOID)

remote_virtual_free = typed_f(kernel32.VirtualFree,
                              [cw.HANDLE, cw.LPVOID, c.c_size_t, cw.DWORD],
                              c.c_bool)

# Needed when modifying executable memory.
flush_instruction_cache = typed_f(kernel32.FlushInstructionCache,
                                  [cw.HANDLE, cw.LPCVOID, c.c_size_t],
                                  c.c_bool)

remote_write_memory = typed_f(kernel32.WriteProcessMemory,
                              [cw.HANDLE, cw.LPVOID, cw.LPCVOID, c.c_size_t, c.POINTER(c.c_size_t)],
                              c.c_bool)

# FIXME: The second parameter isn't really a void pointer, it's a SECURITY_ATTRIBUTES pointer, but I don't think
#  we need it, and we'd need to define a custom Structure to specify it.
# FIXME: The same goes for the fourth parameter. It's not actually a void pointer; it's a LPTHREAD_START_ROUTINE, which
#  is a pointer to a function that takes a LPVOID (a pointer to a paramater struct), and returns a DWORD.
remote_thread_create = typed_f(kernel32.CreateRemoteThread,
                               [cw.HANDLE, cw.LPVOID, c.c_size_t, cw.LPVOID, cw.LPVOID, cw.DWORD, cw.LPDWORD],
                               cw.HANDLE)


def create_process_snapshot() -> cw.HANDLE:
    return create_snapshot(TH32CS_SNAPPROCESS, -1)


def list_processes() -> Optional[list[PROCESSENTRY32]]:
    """Returns a list of information about all active processes at the time the call is made, or
    None if a snapshot couldn't be taken."""
    snapshot = create_process_snapshot()

    if snapshot == INVALID_HANDLE_VALUE:
        return None

    try:
        proc_entry = PROCESSENTRY32()
        proc_entry.dwSize = c.sizeof(PROCESSENTRY32)
        read_success = first_process(snapshot, c.byref(proc_entry))

        entries = []
        while True:
            if read_success:
                entry_copy = PROCESSENTRY32()
                c.memmove(c.byref(entry_copy), c.byref(proc_entry), proc_entry.dwSize)
                entries.append(entry_copy)
            else:
                break
            read_success = next_process(snapshot, c.byref(proc_entry))
    finally:
        close_handle(snapshot)

    return entries


def get_process_ids(process_name: bytes) -> Iterator[int]:
    """Returns all process IDs at the time of calling, or nothing if a list of processes couldn't be obtained."""
    processes = list_processes()
    if processes is None:
        return

    for proc in processes:
        if proc.szExeFile == process_name:
            yield proc.th32ProcessID


def formatted_last_error(task_message: str) -> str:
    return f"Failed to {task_message}. Error: {kernel32.GetLastError()}"


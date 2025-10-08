import ida_dbg
import ida_idaapi
import ida_ida
import ida_kernwin
import os
import subprocess

def get_debugged_process_pid():
    """
    Retrieves the Process ID (PID) of the currently debugged process.
    """
    if ida_dbg.get_process_state() == ida_dbg.DSTATE_NOTASK:
        return -1
    event = ida_dbg.get_debug_event()
    return event.pid if event else -1

# --- Konfiguracja ---
INJECTOR_EXE_X86 = "InjectorCLIx86.exe"
INJECTOR_EXE_X64 = "InjectorCLIx64.exe"
HOOK_DLL_X86 = "HookLibraryx86.dll"
HOOK_DLL_X64 = "HookLibraryx64.dll"
# --- Koniec Konfiguracji ---

class ScyllaInjectorPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL
    comment = "Injects ScyllaHide into the current debugged process"
    help = "Run this plugin while a process is suspended in the IDA debugger to inject ScyllaHide."
    wanted_name = "ScyllaHide: Inject into process"
    wanted_hotkey = "Ctrl-Alt-S"

    def init(self):
        ida_kernwin.msg("ScyllaHide Injector plugin loaded.\n")
        return ida_idaapi.PLUGIN_OK

    def term(self):
        pass

    def run(self, arg):
        ida_kernwin.msg("--- ScyllaHide Auto-Injector ---\n")

        # 1. Get the Process ID (PID) of the currently debugged process
        pid = get_debugged_process_pid()

        if pid == -1:
            ida_kernwin.warning("Could not determine the PID of the debugged process. Is a process being debugged and suspended?")
            return

        ida_kernwin.msg(f"Using PID: {pid}\n")

        # 2. Use the PID to perform injection
        plugin_path = os.path.dirname(os.path.abspath(__file__))
        is_64bit = ida_ida.inf_is_64bit()

        if is_64bit:
            injector_path = os.path.join(plugin_path, INJECTOR_EXE_X64)
            dll_path = os.path.join(plugin_path, HOOK_DLL_X64)
        else:
            injector_path = os.path.join(plugin_path, INJECTOR_EXE_X86)
            dll_path = os.path.join(plugin_path, HOOK_DLL_X86)

        if not os.path.exists(injector_path) or not os.path.exists(dll_path):
            ida_kernwin.warning(f"Error: Injector or DLL not found.\n")
            return

        ida_kernwin.msg(f"Using Injector: {os.path.basename(injector_path)}\n")
        ida_kernwin.msg(f"Using DLL: {os.path.basename(dll_path)}\n")

        command = [injector_path, f"pid:{pid}", dll_path]
        ida_kernwin.msg(f"Executing command: {' '.join(command)}\n")

        try:
            result = subprocess.run(
                command, capture_output=True, text=True, check=False,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            ida_kernwin.msg("\n--- Injector Output ---\n")
            if result.stdout:
                ida_kernwin.msg(result.stdout)
            if result.stderr:
                ida_kernwin.warning(result.stderr)
            ida_kernwin.msg("--- End Injector Output ---\n")
            if result.returncode == 0:
                ida_kernwin.msg("Injection command executed successfully.\n")
            else:
                ida_kernwin.warning(f"Injector exited with code {result.returncode}.\n")
        except Exception as e:
            ida_kernwin.warning(f"An unexpected error occurred: {e}\n")

        ida_kernwin.msg("------------------------------------\n")
        ida_kernwin.msg("You can now resume the process in IDA (F9).\n")

def PLUGIN_ENTRY():
    return ScyllaInjectorPlugin()

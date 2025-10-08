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

def start_process_with_options():
    """
    Starts a new process for debugging using the settings from "Process options".
    """
    path, args, sdir, host, passwd, port = ida_dbg.get_process_options()

    if not path:
        ida_kernwin.warning("Process path is not configured in 'Debugger > Process options'.")
        return False

    ida_kernwin.msg(f"Starting process: {path}\n")
    
    # start_process with None arguments uses the settings from Process Options
    result = ida_dbg.start_process(None, None, None)

    if result == 1:
        ida_kernwin.msg("Process started successfully. Waiting for IDA to suspend...\n")
        return True
    elif result == 0:
        ida_kernwin.warning("Process start cancelled by user.\n")
    else:
        ida_kernwin.warning("Failed to start process. Check debugger settings and output log.\n")
    return False


# --- Konfiguracja ---
INJECTOR_EXE_X86 = "InjectorCLIx86.exe"
INJECTOR_EXE_X64 = "InjectorCLIx64.exe"
HOOK_DLL_X86 = "HookLibraryx86.dll"
HOOK_DLL_X64 = "HookLibraryx64.dll"
# --- Koniec Konfiguracji ---

class InjectHandler(ida_kernwin.action_handler_t):
    """Action handler for injecting into the current debugged process."""
    def __init__(self, plugin_instance):
        ida_kernwin.action_handler_t.__init__(self)
        self.plugin = plugin_instance

    def activate(self, ctx):
        self.plugin.inject_scylla()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ScyllaStartHook(ida_dbg.DBG_Hooks):
    """
    A temporary debugger hook to inject ScyllaHide as soon as the process
    is started and suspended for the first time.
    """
    def __init__(self, plugin_instance):
        super(ScyllaStartHook, self).__init__()
        self.plugin = plugin_instance

    def dbg_suspend_process(self, *args):
        ida_kernwin.msg("Process suspended. Now injecting ScyllaHide...\n")
        
        # 1. Perform the injection
        self.plugin.inject_scylla()
        
        # 2. Unhook and clean up to avoid being called again
        self.unhook()
        return 0

class StartAndInjectHandler(ida_kernwin.action_handler_t):
    """Action handler for starting a new process and then injecting."""
    def __init__(self, plugin_instance):
        ida_kernwin.action_handler_t.__init__(self)
        self.plugin = plugin_instance

    def activate(self, ctx):
        ida_kernwin.msg("--- ScyllaHide Auto-Starter & Injector ---\n")

        # 1. Check if a process is already running
        if ida_dbg.get_process_state() != ida_dbg.DSTATE_NOTASK:
            ida_kernwin.warning("A process is already being debugged. Please terminate it first.")
            return 1

        # 2. Install a temporary hook that will trigger the injection on suspend.
        self.hook = ScyllaStartHook(self.plugin)
        self.hook.hook()
        ida_kernwin.msg("Hook installed. Starting process...\n")

        # 3. Start the process. The hook will take care of the injection.
        if start_process_with_options():
            ida_kernwin.msg("Process start command sent. Waiting for suspend event...\n")
        else:
            ida_kernwin.msg("Process did not start. Aborting.\n")
            self.hook.unhook() # Clean up the hook if process fails to start

        ida_kernwin.msg("-------------------------------------------\n")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ScyllaInjectorPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL
    comment = "Injects ScyllaHide into processes"
    help = "Use 'ScyllaHide: Inject into process' while a process is suspended in the IDA debugger to inject ScyllaHide."
    wanted_name = "ScyllaHide Injector"
    wanted_hotkey = ""

    def init(self):
        ida_kernwin.msg("ScyllaHide Injector plugin loaded.\n")

        # Register the "Inject" action
        inject_action_desc = ida_kernwin.action_desc_t(
            'scylla:inject',
            'ScyllaHide: Inject into process',
            InjectHandler(self),
            'Ctrl-Alt-S')
        ida_kernwin.register_action(inject_action_desc)
        ida_kernwin.attach_action_to_menu('Debugger/ScyllaHide/', 'scylla:inject', ida_kernwin.SETMENU_APP)

        # Register the "Start and Inject" action
        start_inject_action_desc = ida_kernwin.action_desc_t(
            'scylla:start_and_inject',
            'ScyllaHide: Start process and inject',
            StartAndInjectHandler(self),
            'Ctrl-Alt-R')
        ida_kernwin.register_action(start_inject_action_desc)
        ida_kernwin.attach_action_to_menu('Debugger/ScyllaHide/', 'scylla:start_and_inject', ida_kernwin.SETMENU_APP)

        # Create a toolbar and add the actions
        ida_kernwin.create_toolbar("ScyllaHideToolbar", "ScyllaHide")
        ida_kernwin.attach_action_to_toolbar("ScyllaHideToolbar", "scylla:inject")
        ida_kernwin.attach_action_to_toolbar("ScyllaHideToolbar", "scylla:start_and_inject")

        return ida_idaapi.PLUGIN_OK

    def term(self):
        ida_kernwin.delete_toolbar("ScyllaHideToolbar")
        ida_kernwin.unregister_action('scylla:inject')
        ida_kernwin.unregister_action('scylla:start_and_inject')
        ida_kernwin.msg("ScyllaHide Injector plugin unloaded.\n")

    def run(self, arg):
        # This is now just a placeholder, as actions are used.
        ida_kernwin.msg("Please use the 'Debugger > ScyllaHide' menu.\n")

    def inject_scylla(self):
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
            # Launch the injector in a new console window.
            # This allows the user to see the output and prevents IDA from blocking.
            subprocess.Popen(
                command,
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            ida_kernwin.msg("Injection command sent to the injector process.\n")
        except Exception as e:
            ida_kernwin.warning(f"An unexpected error occurred while launching the injector: {e}\n")

        ida_kernwin.msg("------------------------------------\n")
        ida_kernwin.msg("You can now resume the process in IDA (F9).\n")

def PLUGIN_ENTRY():
    return ScyllaInjectorPlugin()
 
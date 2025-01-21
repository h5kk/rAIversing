"""
IDA Pro plugin loader for rAIversing
Place this file in IDA's plugins directory
"""

import ida_idaapi
import ida_kernwin

PLUGIN_NAME = "rAIversing"
PLUGIN_HOTKEY = ""
PLUGIN_MENU_PATH = "Edit/rAIversing/"

# Import the main script functions
import raiversing_script

class RAIversingPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL
    comment = "AI-powered reverse engineering assistant"
    help = "Improves function names and adds documentation"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY
    
    def init(self):
        """
        Called when IDA loads the plugin.
        """
        try:
            print("\nInitializing rAIversing plugin...")
            raiversing_script.register_actions()
            print("rAIversing plugin loaded successfully!")
            return ida_idaapi.PLUGIN_OK
        except Exception as e:
            print(f"Failed to initialize rAIversing plugin: {str(e)}")
            return ida_idaapi.PLUGIN_SKIP
    
    def run(self, arg):
        """
        Called when the plugin is run.
        """
        pass
    
    def term(self):
        """
        Called when the plugin is unloaded.
        """
        try:
            # Unregister actions
            for action_id in ["raiversing:improve_all", "raiversing:improve_current"]:
                ida_kernwin.unregister_action(action_id)
        except:
            pass

def PLUGIN_ENTRY():
    return RAIversingPlugin() 
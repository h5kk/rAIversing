import ida_idaapi
import ida_kernwin
from . import __main__ as raiversing_main

PLUGIN_NAME = "rAIversing"
PLUGIN_HOTKEY = "Ctrl-Alt-R"
PLUGIN_MENU_PATH = "Edit/rAIversing"

class RAIversingPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL
    comment = "AI-powered reverse engineering assistant"
    help = "Uses GPT-4 to analyze and improve function names"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY
    
    def init(self):
        """
        Called when IDA loads the plugin.
        """
        # Register menu item
        ida_kernwin.attach_action_to_menu(
            PLUGIN_MENU_PATH,
            PLUGIN_NAME,
            ida_kernwin.SETMENU_APP
        )
        return ida_idaapi.PLUGIN_OK
        
    def run(self, arg):
        """
        Called when the plugin is executed.
        """
        raiversing_main.main()
        
    def term(self):
        """
        Called when the plugin is unloaded.
        """
        ida_kernwin.detach_action_from_menu(
            PLUGIN_MENU_PATH,
            PLUGIN_NAME
        )

def PLUGIN_ENTRY():
    return RAIversingPlugin() 
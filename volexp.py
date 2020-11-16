#!/usr/bin/python
# VolExp
# Author: Aviel Zohar
# See license information on VolExp github page: https://github.com/memoryforensics1/VolExp
# Contact: memoryforensicsanalysis@gmail.com
# Description:
# This programs allows you to analyze a memory image (also supported as a volatility plugin)
# using a gui app very similar to process hacker/explorer.
# For more information and help go to the github page above
# To get offline help use the menu: Help->Display Help or press F11.
# Imports
import urllib					# virustotal check.
from webbrowser import open_new # go to github page
import StringIO, string, pickle, re
import os, sys, time, logging, random, copy
import threading, Queue, subprocess, inspect, functools
import turtle, ttk
from ttk import Frame, Treeview, Scrollbar, Progressbar, Combobox
import Tkinter as tk
from Tkinter import N, E, W, S, END, YES, BOTH, PanedWindow, Tk, LEFT, Menu, StringVar, RIGHT, HORIZONTAL, X, Y, BOTTOM, Text, NONE, SOLID, TOP, INSERT
import tkFont
import tkFileDialog
import tkColorChooser
import tkSimpleDialog
import ScrolledText as scrolledtext
import tkMessageBox as messagebox
import volatility.obj as obj
import volatility.conf as conf
import volatility.win32 as win32
import volatility.debug as debug
import volatility.utils as utils
import volatility.commands as commands
import volatility.registry as registry
import volatility.win32.tasks as tasks
import volatility.win32.rawreg as rawreg
import volatility.plugins.common as common
import volatility.plugins.vadinfo as vadinfo
import volatility.plugins.filescan as filescan
import volatility.plugins.procdump as procdump
import volatility.plugins.mftparser as mftparser
import volatility.plugins.dumpfiles as dumpfiles
import volatility.plugins.privileges as privileges

#region Try imports
try:
    from ttkthemes import ThemedStyle
    has_themes = True
except ImportError:
    has_themes = False
    print "Install ttkthemes for better themes on volexp"

try:
    import volatility.plugins.getsids as getsids
    import volatility.plugins.registry.registryapi as registryapi
    has_crypto = True
except Exception as ex:
    has_crypto = False
    debug.warning("Please install pycrypto to get the user name of any process\nand explore the registry. {}".format(ex))

try:
    import distorm3
    has_distorm = True
except ImportError:
    has_distorm = False
    debug.warning("Please install distorm3 to see disassemble stuff..")

try:
    import volatility.plugins.winobj as winobj
    has_winobj = True
except Exception as ex:
    try:
        import volatility.plugins.community.winobj as winobj
    except Exception as ex:
        has_winobj = False
        debug.warning("You get this error because you dont have the winobj plugin (by shachaf atun[kslgroup]), Please download this plugin for enumerate object in gui.\nThe Error:\n {}".format(ex))

try:
    import requests
    has_requests = True
except ImportError:
    has_requests = False
    debug.warning('to run this plugin using virustotal result please install requests module (run on shell "pip install requests")')

try:
    import csv
    has_csv = True
except ImportError:
    has_csv = False

#endregion Try Imports

#region add vtypes
#ACE (Access Control Entry) structs (from Cem Gurkok)
ace_types = {
    '_ACE' : [0x14, {
        'Header' : [0x0, ['_ACE_HEADER']],
        'ProcessMask' : [0x4, ['Flags', {'target': 'unsigned int', 'bitmap': {
                                                                        "PROCESS_TERMINATE":0,
                                                                        "PROCESS_CREATE_THREAD":2,
                                                                        "PROCESS_VM_OPERATION":3,
                                                                        "PROCESS_VM_READ":4,
                                                                        "PROCESS_VM_WRITE":5,
                                                                        "PROCESS_DUP_HANDLE":6,
                                                                        "PROCESS_CREATE_PROCESS":7,
                                                                        "PROCESS_SET_QUOTA":8,
                                                                        "PROCESS_SET_INFORMATION":9,
                                                                        "PROCESS_QUERY_INFORMATION":10,
                                                                        "PROCESS_SUSPEND_RESUME":11,
                                                                        "PROCESS_QUERY_LIMITED_INFORMATION":12,
                                                                        "Read DAC":17,
                                                                        "Write DAC":18,
                                                                        "Write Owner":19,
                                                                        "Synchronize":20,
                                                                        "SACL Access":24,
                                                                        "ACCESS_SYSTEM_SECURITY":25,
                                                                        "Generic All":28,
                                                                        "Generic Execute":29,
                                                                        "Generic Write":30,
                                                                        "Generic Read":31
                                                                        }}]],
        'ServiceMask' : [0x4, ['Flags', {'target': 'unsigned int', 'bitmap': {
                                                                        "SERVICE_QUERY_CONFIG":0,
                                                                        "SERVICE_CHANGE_CONFIG":1,
                                                                        "SERVICE_QUERY_STATUS":2,
                                                                        "SERVICE_ENUMERATE_DEPENDENTS":3,
                                                                        "SERVICE_START":4,
                                                                        "SERVICE_STOP":5,
                                                                        "SERVICE_PAUSE_CONTINUE":6,
                                                                        "SERVICE_INTERROGATE":7,
                                                                        "SERVICE_USER_DEFINED_CONTROL":8,
                                                                        "Read DAC":17,
                                                                        "Write DAC":18,
                                                                        "Write Owner":19,
                                                                        "Synchronize":20,
                                                                        "SACL Access":24,
                                                                        "ACCESS_SYSTEM_SECURITY":25,
                                                                        "Generic All":28,
                                                                        "Generic Execute":29,
                                                                        "Generic Write":30,
                                                                        "Generic Read":31
                                                                        }}]],
        'ThreadMask' : [0x4, ['Flags', {'target': 'unsigned int', 'bitmap': {
                                                                        "THREAD_TERMINATE":0,
                                                                        "THREAD_SUSPEND_RESUME":1,
                                                                        "THREAD_GET_CONTEXT":3,
                                                                        "THREAD_SET_CONTEXT":4,
                                                                        "THREAD_SET_INFORMATION":5,
                                                                        "THREAD_QUERY_INFORMATION":6,
                                                                        "THREAD_SET_THREAD_TOKEN":7,
                                                                        "THREAD_IMPERSONATE":8,
                                                                        "THREAD_DIRECT_IMPERSONATION":9,
                                                                        "THREAD_QUERY_LIMITED_INFORMATION":11,
                                                                        "THREAD_SET_LIMITED_INFORMATION":10,
                                                                        "Read DAC":17,
                                                                        "Write DAC":18,
                                                                        "Write Owner":19,
                                                                        "Synchronize":20,
                                                                        "SACL Access":24,
                                                                        "ACCESS_SYSTEM_SECURITY":25,
                                                                        "Generic All":28,
                                                                        "Generic Execute":29,
                                                                        "Generic Write":30,
                                                                        "Generic Read":31
                                                                        }}]],
        'TokenMask' : [0x4, ['Flags', {'target': 'unsigned int', 'bitmap': {
                                                                        "TOKEN_ASSIGN_PRIMARY":0,
                                                                        "TOKEN_DUPLICATE":1,
                                                                        "TOKEN_IMPERSONATE":2,
                                                                        "TOKEN_QUERY":3,
                                                                        "TOKEN_QUERY_SOURCE":4,
                                                                        "TOKEN_ADJUST_PRIVILEGES":5,
                                                                        "TOKEN_ADJUST_GROUPS":6,
                                                                        "TOKEN_ADJUST_DEFAULT":7,
                                                                        "TOKEN_ADJUST_SESSIONID":8,
                                                                        "Read DAC":17,
                                                                        "Write DAC":18,
                                                                        "Write Owner":19,
                                                                        "Synchronize":20,
                                                                        "SACL Access":24,
                                                                        "ACCESS_SYSTEM_SECURITY":25,
                                                                        "Generic All":28,
                                                                        "Generic Execute":29,
                                                                        "Generic Write":30,
                                                                        "Generic Read":31
                                                                        }}]],
        'RegistryMask' : [0x4, ['Flags', {'target': 'unsigned int', 'bitmap': {
                                                                        "KEY_QUERY_VALUE":0,
                                                                        "KEY_SET_VALUE":1,
                                                                        "KEY_CREATE_SUB_KEY ":2,
                                                                        "KEY_ENUMERATE_SUB_KEYS ":3,
                                                                        "KEY_NOTIFY":4,
                                                                        "KEY_CREATE_LINK ":5,
                                                                        "KEY_WOW64_64KEY":8,
                                                                        "KEY_WOW64_32KEY":9,
                                                                        "Read DAC":17,
                                                                        "Write DAC":18,
                                                                        "Write Owner":19,
                                                                        "Synchronize":20,
                                                                        "SACL Access":24,
                                                                        "ACCESS_SYSTEM_SECURITY":25,
                                                                        "Generic All":28,
                                                                        "Generic Execute":29,
                                                                        "Generic Write":30,
                                                                        "Generic Read":31
                                                                        }}]],
        'FileMask' : [0x4, ['Flags', {'target': 'unsigned int', 'bitmap': {
                                                                        "FILE_READ_DATA":0,
                                                                        "FILE_WRITE_DATA":1,
                                                                        "FILE_APPEND_DATA":2,
                                                                        "FILE_READ_EA":3,
                                                                        "FILE_WRITE_EA":4,
                                                                        "FILE_EXECUTE":5,
                                                                        "FILE_READ_ATTRIBUTES":7,
                                                                        "FILE_WRITE_ATTRIBUTES":8,
                                                                        "Read DAC":17,
                                                                        "Write DAC":18,
                                                                        "Write Owner":19,
                                                                        "Synchronize":20,
                                                                        "SACL Access":24,
                                                                        "ACCESS_SYSTEM_SECURITY":25,
                                                                        "Generic All":28,
                                                                        "Generic Execute":29,
                                                                        "Generic Write":30,
                                                                        "Generic Read":31
                                                                        }}]],
        'SidStart' : [0x8, ['unsigned int']]
    }],
    '_ACE_HEADER' : [0x4, {
        'Type' : [0x0, ['Enumeration', {'target' : 'unsigned char', 'choices': {
                                                                        0:"ACCESS_ALLOWED",
                                                                        1:"ACCESS_DENIED",
                                                                        2:"SYSTEM_AUDIT",
                                                                        3:"SYSTEM_ALARM",
                                                                        4:"ACCESS_ALLOWED_COMPOUND",
                                                                        5:"ACCESS_ALLOWED_OBJECT",
                                                                        6:"ACCESS_DENIED_OBJECT",
                                                                        7:"SYSTEM_AUDIT_OBJECT",
                                                                        8:"SYSTEM_ALARM_OBJECT",
                                                                        9:"ACCESS_ALLOWED_CALLBACK",
                                                                        10:"ACCESS_DENIED_CALLBACK",
                                                                        11:"ACCESS_ALLOWED_CALLBACK_OBJECT",
                                                                        12:"ACCESS_DENIED_CALLBACK_OBJECT",
                                                                        13:"SYSTEM_AUDIT_CALLBACK",
                                                                        14:"SYSTEM_ALARM_CALLBACK",
                                                                        15:"SYSTEM_AUDIT_CALLBACK_OBJECT",
                                                                        16:"SYSTEM_ALARM_CALLBACK_OBJECT",
                                                                        17:"SYSTEM_MANDATORY_LABEL"
                                                                        }}]],
        'Flags': [0x1, ['Flags', {'target': 'unsigned char', 'bitmap': {
                                                                        "OBJECT_INHERIT_ACE":1,
                                                                        "CONTAINER_INHERIT_ACE":2,
                                                                        "INHERIT_ONLY_ACE":4,
                                                                        "NO_PROPAGATE_INHERIT_ACE":3,
                                                                        "INHERITED_ACE":5
                                                                        }}]],
        'Size': [0x2,['unsigned short']]
    }],
}

class _ACE_HEADER(obj.CType):
    """ ace header type """

class _ACE(obj.CType):
    """ ace type """

#add ACE vtypes
class ACEObject(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'windows'}
    before = ['BasicObjectClasses']

    def modification(self, profile):
        profile.vtypes.update(ace_types)
#endregion add vtypes

#region Constans and globals
# all the globals kept here.
# also the icon images save here encoded with base-64 to make the plugin only one file.

right_click_event = '<Button-2>' if sys.platform == 'darwin' else '<Button-3>'

ICON = \
"""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
"""

EXP_SEARCH_ICON = \
"""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
6D83N37PA0BAAAA7"""

MAIN_PROPERTIES_ICON = \
"""R0lGODlhyADIAHAAACwAAAAAyADIAIf////+/v79/f38/Pz7+/v6+vr4+Pj5+fn19fX29vb39/f0
9PTb29u5ubmoqKilpaWgoKClpaSioqKkpKShoaGjo6Oqqqq/v7/c3Nze3t5YWFdNTU1MTExNTUye
np3p6eljY2N0dHTFxcWFhYXw8PDx8fFOTk7a2tqenp7d3d2ZmZlPT0/q6uqTk5OSkpKIiIiKioqE
hIR/f3/y8vKBgYHKysp8fHyHh4dzc3N5eXlkZGR1dXVfX1+mpqZubm5hYWGkpKNWVlZgYGBcXFxV
VVVZWVlYWFhSUlLR0dFQUFDZ2dnt7e1RUVF4eHjz8/Ovr69mZmanp6e2trbY2Nh2dnZlZWWwsLDs
7OzCwsK1tbVXV1epqamzs7OsrKxTU1OVlZVUVFTT09OamppnZ2fj4+O4uLjv7+/MzMy6urrf399i
YmKrq6tdXV1dXVycnJybm5vl5eXr6+ucnJvU1NRoaGdpaWnPz8/GxsbOzs7S0tLb29qMjIxbW1vk
5OSgoJ/o6OhycnJxcXHHx8fu7u5aWlrh4eHm5uZQUE/X19fi4uLW1taJiYm+vr7n5+dWVlWAgIBt
bW3V1dVqamqfn5/Pz85oaGitra3k5OO9vb3JycnQ0NDIyMjNzc1mZmVVVVR0dHNsbGyYmJidnZ28
vLyUlJSLi4uPj4+urq4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI/wABCBxI
sKDBgwgTKlzIsKHDhxAjSpxIsaLFixgzatzI0eKgjgk/gjwocmTDkiYHoiRpcNBKAC5ZFnwJUybB
mCdt3mxJk+RLmj+D6hQIdCjMngp/Gj3Kc6bQmT6bOp0KVepOq0SVtoxKVeXTq12NFt1KtirYm1rN
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
"""

LOWER_PANE_ICON = \
"""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
gxtcJDHVVF3VVn3VWJ3VWr3VXN3VXv3VVB0QADs=
"""

SEARCH_ICON = \
"""R0lGODlhyQDJAHAAACH5BAEAAP8ALAAAAADJAMkAh////ykhIQAAAM4pQu/372NSWu/m770pMTo6
OpRKWt7Fzr3FxXNzlObm3pRzYxBKYxBKvWucnBAZlBAZ75QZY5QZvcXvtUIZY0IZvWsZY2sZvSkp
KUJKWhAIEJTFnJTFGWvF3mvFWmvFnGvFGULO3kLOWkLOnELOGRDv3hDvWhDvnBDvGb3FWr2MGb2l
Wr1rGZQZOkpKQhBKOpRKjEJKjOYQa70QYxBKlBBK75RKvUJKvb0QEGtKjGtKvd4ZQlIZMYyEhJSc
Y0IZlJQZlEIZ75QZ72ucY2sZlGsZ75RCOt69reZ7a+aMrb1S7729Kb1Srb2M770Z770Zrea9jOZ7
SuaMjL1Szr29CL1SjL2Mzr0Zzr0ZjLWtrbVCY7WMjNbe3pSUlLWMre/FWkLv3kLvWkLvnELvGe+M
Ge+lWu9rGbU6QrVzazExMZRK70JK7729773vjL3vOmtK773vY73vEHMZMea97+ZCa+ZCKeYQKeZC
SuZCCOYQCDpKEBAIYxAIvXNzc+9S7++9Ke9Sre+M7+8Z7+8ZrVIZEJQZEL17Su9Szu+9CO9SjO+M
zu8Zzu8ZjHMZEGtzWrVCKXNKOu/vjO/vOr29te/vY+/vEJR7zpR7EGt7zmt7EL3v5hAIOhBSEBCl
7xClaxClrRClKZRKEBB77xB7axB7rRB7KRDO7xDOaxDOrRDOKbW9lO/vtb1CCBAxEBClzhClShCl
jBClCHNKEBB7zhB7ShB7jBB7CBDOzhDOShDOjBDOCDEZMZycpTEZEFpKEBApYxApvZTv75Tva0Kl
70Kla0KlrUKlKZTvrZTvKWvv72vva2vvrWvvKZTF75TFa0J770J7a0J7rUJ7KZR775R7MWt772t7
MZSczpScEGuczmucEJTvzpTvSkKlzkKlSkKljEKlCJTvjJTvCGvvzmvvSmvvjGvvCJTFzpTFSkJ7
zkJ7SkJ7jEJ7CJSc75ScMWuc72ucMZR7pRApOhkhGc7v/70QQr0QMRAIALUpQv/m/ykhCAAQAAAA
AAj/AAEIHEiwoMGDCBMqXMiwocOHECNKnEixosWLGDNq3Mixo8ePIEOKHEmypMmTKFOqXMmypcuX
MGPKnEmzps2bOHPq3Mmzp8+fQIMKHUq0qNGjSJMqXcq0qdOnUKNKnUq1qtWrWLNq3cq1q9evSw2A
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
"""

PROPERTIES_ICON = \
"""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
"""

SAVE_ICON = \
"""R0lGODlhyADIAHAAACwAAAAAyADIAIf39/f///+c3vcZY5wQWowQUnsQQmsQSnMZWpQIUowIWpS1
tbUQQnsAIToAIUIAKVLW1t7e5t4AMVoAEDHv7+8AKUIAGSm9vb0AMVLWzs4AMWPO7/e15vcZUoTF
zs69vcUpSmPm5q3m5jqt5jrm5hCt5hDm5mOt5mPmGRCtGRBCGc5Ka4wAEBkQc9bv//cIITGl3tbm
ShDmrRCtShCtrRBCSs5zGc7mexCtexAxnJwQnN5axd5a795a71p7e1oQ794Q71pa75xa7xkQ75wQ
7xlaxVoQxd4QxVpaxZxaxRkQxZwQxRkQe1paexkQexnm5oTmUrWtUrWt5oTmGbWtGbXmGTGtGTFC
Ge97GVrmGXNzGaVzGSmtGXM6GSmtjO/mUpStUpTmGZStGZRaGVrmGVJzGYRzGQitGVI6GQitjM7W
UuacUubWGeacGeZac2NanNZze5wpQkp7e95zSs5SlJQQOrUQELWlteYxe957SlrmrXPmSnPmSjFz
SqXmrTFzSimtSjGtrTGtSnM6SilCSu+trXOlnKVzGe/mezGtezE6GaXme3Ote3PmhO/vhKVaSlrm
rVLmSlJzSoRzSgitSlI6SgitrVKle6U6GYTme1Kte1LmhM7OhKUxCFopc5x7vd4Ic6V7795771p7
nFox794x71p775x77xkx75wx7xkQGYR7xVoxxd4xxVp7xZx7xRkxxZwxxRlSnFoInJwQnFpanBkQ
nBkxe1p7exkxexl7nNYZWoRznJwQOuYQEOb3Uua9Uub3Gea9GeY6SoRzSu86SqUIQnPmte/vtaW9
5q3mtc7OtaWc5q0xnN4IMRkxnFp7nBkxnBkIUhkxKVpae84IMVoAEDoIWq0QWuZae+8IEGOcvZwI
QkIIUlrW1u/F5tbm5s4QQlqt1u/31ve1vZzv797v1t6U7/fmzs6ltb0ACCkIIToZQowAQoQIKWMI
WpyUzvcAWoQAQloAUnMQWnMZUpz/9/fv9+8QWnsAUnv//+/v9/f39/+U3v+U3u+c3u8I/wADCBxI
sKDBgwgTKlzIsKHDhxAjSpy4kILFixgzatzIsaPHjyBDihxJsqTJkxwDUFApcCXLly5jtpwJk6bM
mjhv6rTJM2fPnT6DAh36s6hQo0R5WmS5smlTpiqfSpXKlKpTqFetWo2KlavWrku/isW6NSxZsGXT
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
9t9PfbW/+9tH/tWv/eeH24AAADs=
"""

HELP_ME = \
"""
Volatility Explorer Help:

This program can run as a plugin of Volatility or as a separate process (which will use Volatility API and some of its plugins).
In this Help window, shortcuts will be displayed inside a parentheses [].

Main process tab:
    Menu:
        File:
            Save / Save As - Save the current state of the analysis to load later (.atz file type).
            Exit - Exit the program.

        View:
            Open Sub View:
                <Sub View Name> - Open a new view as another tab to the main tabs.
            
            Registry Explorer [ctrl+r]- A regedit-like tool that shows all the keys found in this specific image
            Runs automatically on first load.
            Click "View Keys" to view key data (using Volatility registryapi).
            
            MFT Explorer [ctrl+m]- Explorer-like tool that contains all the files and directories
            (a little bit verbose but there is a search bar [ctrl+s] to help you) with timestamps and 
            other MFT data (using mftparsegui plugin which uses the mftparser plugin).

            File Explorer [ctrl+e]- Explorer-like tool that contains all the files and directories inside,
            capable of dumping a single file and has a search bar [ctrl+s] 
            (using filescangui plugin which uses the filescan plugin).

            WinObj Explorer [ctrl+w]- Explorer-like tool that contains all the Windows objects in their directories
            (similar to winobj from sysinternals), has a search bar to help you [ctrl+s], 
            (using winobjgui plugin which uses winobj plugin).

            Process Tree [ctrl+t]- If you want to get the process tree in the right order again (after ordering by a coulumn)

            System Information [ctrl+i]- Show related system information.

            Services [ctrl+s]- Display all the services in this memory dump with related information (using svcscan plugin).
            
            Select Columns [ctrl+c] - Allows you to select a column from all the available columns for this table.
            
        Process:
            Dlls [ctrl+d]- Display all of the dlls of the pressed process.
            
            Handles [ctrl+h]- Display all of the handles of the pressed process.
            
            Network [ctrl+n]- Display all of the network information of the pressed process.

        Find:
            Find Handles and Dlls - Search for handles and dlls in all of the processes 
            (double click on the result will go to the process and the dll/handle pressed).

        Plugins:
            <Plugin Name> [ctrl+p]- Run the specific plugin pressed and display it in another process, cmd-like gui 
            (you can run another plugin from there).

        Dump:
            Dump Registry Hives - Dump all hives files (using dumpregistry plugin).
            
            Dump Event Log - Dump event log files (dump .evtx files, using dumpfiles plugin).
            
            Dump Certs - Dump all certificates from memory (using dumpcerts plugin).

        Options:
            Options [ctrl+o]- Show options menu and allows you to change different options.

    Process Right Click:
        Copy:
            <Field Name> - Copy this specific field from the selected process to the clipboard.

        ProcDump - Dump this process.

        HexDump - Dump this process and display a HexDump of this process file.

        Color:
            <Color> - Allows you to color processes as suspicious|clean for your analysis
            (Recommended: Take a note why this process is suspicious|clean in the properties>image tab).

        Plugins:
            <Plugin Name> - Run the specific plugin on the pressed process 
            (Volatility ...<plugin name> -p <process pid>) and displays it in a 
            new tab on the specific process->properties-><plugin name>.

        Virus Total:
            Upload To VirusTotal - Dump this file and upload it to VirusTotal
            VirusTotal (Check Hash) - Check the hash of this file with the VirusTotal database (without uploading).
            
        Vad Information - Display all the memory mapped regions of this process with detailed information (by analyzing the vads).

        Struct Analysis - Run structanalysis plugin with type _EPROCESS and the address of 
            the pressed process's _EPROCESS struct to analyze the specific _EPROCESS struct.

        Properties [Double Click]- Open properties tab:
            Image - Display process basic information, 
            has a comment tab and buttons to go to the process's working directory and file path.

            Imports - Display all the process's imports
            (if you can't click this tab it means that the impscan plugin didn't run on this process yet,
            try again later, but if there is an empty table then the plugin didn't find anything).

            Performance - Display process's performance information.

            Services - Display all the services related to this process (using svcscan plugin).

            Threads - Display all the process's threads, 
                HexDump [Double Click]- will display the HexDump dissasmbly of the start address of the thread.
                Struct Analysis - open a new tab with structanalyze plugin.
            
            
            TcpIp - Display all network information (using netscan plugin).

            Security - Display all the security related information 
            (using both privs and getsids plugins.
            If both tables don't show it means the plugins didn't finish running).

            Environment - Display all the process environment variables.

            Job - Display all the process's connected jobs.

    PE Right Click:
        Copy:
            <Field Name> - Copy this specific field from the selected dll to the clipboard.

        Dump PE - Dump this PE.

        HexDump - Dump this PE and display a HexDump of this PE file.
        
        Color:
            <Color> - Allows you to color the PE as suspicious|clean for your analysis
            (Recommended: take a note why this PE is suspicious|clean in the properties>PEimage tab of that PE).
        
        Properties [Double Click]- Open properties tab:
            Note! This option will run in real time --> it may take a couple of seconds.
            
            PEImage - Display process basic information, 
            has a comment tab (with an option to sticky this comment on this specific PE universally),
            features a button to go to the PE file in Explorer.

            PEImports - Display all the PE imports.
            
            PEImports - Display all the PE exports.

            PEMemStrings - Display the image strings. 
            
            PEImageStrings - Display the strings present in memory.
            
Gui Help:
    Explorer:
        All explorer tabs (File Explorer, MFT Explorer, WinObj Explorer) 
        are Windows-Explorer-like gui that display all the files and directories found,
        in which directories will be colored yellow.
        Each of the explorers has a search bar (ctrl+f).

    Search <somthing>:
        All search tabs (from File Explorer, MFT Explorer, WinObj Explorer) 
        allow you to find files/directories given an attribute of the target file/directory.
        The results will display in a table.
        Double clicking on specific row will jump to this item.

    Registry Viewer (RegView):
        The RegView will display all of its hives, expand the hive/key to 
        display the sub-directories for this hive/key.
        Press the button "Search Data (Slow)" will search and display the path of the current key 
        (while seaching for the data the RegView Gui will be unavailable),
        Double clicking values will display the value data in HexDump.

    HexDump:
        Display the data in hexdump format, there is a tab for string data view only.

    Tables:
        A lot of the gui here are represented by a table with a lot of options:
            Menus:
                Header Menu:
                    Select Columns [ctrl+c]- Allows you to select columns from all the available columns for this table.
                    
                    Default Columns - Return the table columns's state to default.
                    
                    Hide Column - Hide this column.
                    
                    Resize Column [Select on column header]- Resize this column to fit.
                    
                    Resize All Columns - Resize all columns to fit.
                    
                Item Menu:
                    Copy:
                        <Field Name> - Copy this field from the selected item to the clipboard.
            
"""
CREDITS = \
"""
CREDITS:
Special Thanks to:
- Shachaf Atun for helping me better understand the volatility framework
- Yos Klein for helping with spelling
- The Volatility Framework creators for creating this amazing framework :)

External usage:
Python 2.7, volatility framework.

this tool use some of volatility plugins.
"""
AC_LOGO =\
r"""


__/\\\________/\\\________________/\\\\\\_____/\\\\\\\\\\\\\\\_____________________________        
 _\/\\\_______\/\\\_______________\////\\\____\/\\\///////////______________________________       
  _\//\\\______/\\\___________________\/\\\____\/\\\_____________________________/\\\\\\\\\__      
   __\//\\\____/\\\_______/\\\\\_______\/\\\____\/\\\\\\\\\\\______/\\\____/\\\__/\\\/////\\\_     
    ___\//\\\__/\\\______/\\\///\\\_____\/\\\____\/\\\///////______\///\\\/\\\/__\/\\\\\\\\\\__    
     ____\//\\\/\\\______/\\\__\//\\\____\/\\\____\/\\\_______________\///\\\/____\/\\\//////___   
      _____\//\\\\\______\//\\\__/\\\_____\/\\\____\/\\\________________/\\\/\\\___\/\\\_________  
       ______\//\\\________\///\\\\\/____/\\\\\\\\\_\/\\\\\\\\\\\\\\\__/\\\/\///\\\_\/\\\_________ 
        _______\///___________\/////_____\/////////__\///////////////__\///____\///__\///__________

     _____                 _ _                _               _   _                   _____             _
    |  __ \                \|/               | |      ___    | | | |                 |  ___|           | |
    | |  \/ ___   ___   __| | |    _   _  ___| | __  ( _ )   | |_| | __ ___   _____  | |_ _   _ _ __   | |
    | | __ / _ \ / _ \ / _` | |   | | | |/ __| |/ /  / _ \/\ |  _  |/ _` \ \ / / _ \ |  _| | | | '_ \  | |
    | |_\ \ (_) | (_) | (_| | |___| |_| | (__|   <  | (_>  < | | | | (_| |\ V /  __/ | | | |_| | | | | |_|
     \____/\___/ \___/ \__,_|\____/\__,_|\___|_|\_\  \___/\/ \_| |_/\__,_| \_/ \___| \_|  \__,_|_| |_| (_)

"""

TIP_LIST = ['Tip of the investigation\nAll the explorers have a search [ctrl+f] options\n(File Explorer, WinObj Explorer, MFT explorer, Struct Analyze)',
            'Tip of the investigation\nYou can press the Path\Current Directory buttons and its will open an explorer in this path',
            'Tip of the investigation\nMFT explorer is very verbose use ctrl+f (serach) to help your self find the data you wish',
            'Tip of the investigation\nAll explorers search [ctrl+f] have a feature to search on any field you wish\n(File Explorer, WinObj Explorer, MFT explorer, Struct Analyze)',
            'Tip of the investigation\nIf you need more information on something you probebly can get this data using struct analyze',
            'Tip of the investigation\nOn any table you can select\hide some columns (some of them dont display all the information by default)',
            'Tip of the investigation\nOn any table you can rollback to the original order using ctrl+t (unfilter)',
            'Tip of the investigation\nThis is highly recommended to go to winobj \/\Driver\ & \/\Device\ & \/\Callback\ and search for something bad inside the kernel space',]

ASCII = r" 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#\$%&\'\(\)\*\+,-\./:;<=>\?@\[\]\^_`\{\|\}\\\~\t"
ABS_X = 60
ABS_Y = 60
location = ''
dump_dir = ''
profile = ''
api_key = ''
vol_path = ''
save_file_name = None
volself = None
root = None
TreeTable_CULUMNS = {} # an TreeTable global to store all the user preference for the header selected.
files_info = {'/done/': False}
process_dlls = {} # {pid :[dlls name]}
process_handles = {} # {pid: [(handle type, handle val)]}
process_bases = {} # {pid: {proc: _EPROCESS, dlls: {dll name: dll base}, ldr: {dll name: ldr address}}}
process_threads = {} # {pid: {tid:(all thread info)}}
process_connections = {} # {pid: [(connection info)]}
process_imports = {} # {pid: [(import info)]}
process_env_var = {} # {pid: {var: val}}
process_security = {} # {pid: {'Privs': [()]}, {'Groups':[()]}}
process_performance = {} # {pid: (Performance info)}
process_token = {} # {pid: (primary token, user, sessionid)
plugins_output = {} # {pid :(plugin, output)}
process_comments = {'pidColor':{}} # {pid: comment, 'pidColor': {pid: color}} # to add 'pidllor': (color, comment)
pe_comments = {'pid': {}, 'files': {}} # {pid: [comemnt, color], files: [file_path, [comment, collor]]}
user_sids = {} # {sid: user name}
main_table = None
tree_view_data = []
process_tree_data = [] # [()]
pfn_stuff = {}
mft_explorer = {}
files_scan = {}
winobj_dict = {}
reg_dict = {}
service_dict = {}
all_plugins = ['path',[]]
done_run = {'files_info': False, 'process_dlls': process_dlls, 'process_handles': False, 'process_bases': False, 'process_threads': process_threads, 'process_performance': process_performance,
            'process_connections': False, 'process_imports': False,'process_env_var': False, 'process_security': False, 'process_comments': process_comments, 'plugins_output': plugins_output,
            'mft_explorer': False, 'files_scan': False, 'winobj_dict': False, 'tree_view_data': tree_view_data, 'reg_dict': False, 'service_dict': False, 'process_tree_data': process_tree_data}

KNOWN_HIVES = {
'CMI-CreateHive{C4E7BA2B-68E8-499C-B1A1-371AC8D717C7}': 'SAM',
'CMI-CreateHive{2A7FB991-7BBE-4F9D-B91E-7CB51D4737F5}': 'SYSTEM'
}
sd_ctrl_flags = {
    0x0001: 'SE_OWNER_DEFAULTED',
    0x0002: 'SE_GROUP_DEFAULTED',
    0x0004: 'SE_DACL_PRESENT',
    0x0008: 'SE_DACL_DEFAULTED',
    0x0010: 'SE_SACL_PRESENT',
    0x0020: 'SE_SACL_DEFAULTED',
    0x0040: '<Unknown-2**6=0x40>',
    0x0080: '<Unknown-2**7=0x80>',
    0x0100: 'SE_DACL_AUTO_INHERIT_REQ',
    0x0200: 'SE_SACL_AUTO_INHERIT_REQ',
    0x0400: 'SE_DACL_AUTO_INHERITED',
    0x0800: 'SE_SACL_AUTO_INHERITED',
    0x1000: 'SE_DACL_PROTECTED',
    0x2000: 'SE_SACL_PROTECTED',
    0x4000: 'SE_RM_CONTROL_VALID',
    0x8000: 'SE_SELF_RELATIVE'
}

lock = threading.Lock()
queue = Queue.Queue()
job_queue = Queue.Queue()

#endregion Constans and globals

#region global function

def change_widget_state(childList, to_state):
    '''
    This function change the state to all the childList widgets
    :param childList: list of tkinter widgets
    :param to_state: the state to change
    :return: None
    '''
    for child in childList:
        child.configure(state=to_state)

def strings_ascii(buf, n=5):
    """
    This function extract all the ascii string from a buf where its bigger than n
    yield offset, ascii
    """
    reg = "([%s]{%d,})" % (ASCII, n)
    compiled = re.compile(reg)
    for match in compiled.finditer(buf):
        yield hex(match.start()), match.group().decode("ascii")

def strings_unicode(buf, n=5):
    """
    This function extract all the unicode string from a buf where its bigger than n
    yield offset, unicode
    """
    reg = b"((?:[%s]\x00){%d,})" % (ASCII, n) # place null between them
    compiled = re.compile(reg)
    for match in compiled.finditer(buf):
        try:
            yield hex(match.start()), match.group().decode("utf-16")
        except ZeroDivisionError:
            pass

def get_ascii_unicode(buf, as_string=False ,remove_hex=False, n=5):
    """
    This function return a tuple of (list(strings_ascii), list(strings_unicode))
    """
    if as_string:
        return ['{}: {}'.format(c_offset, c_string) for c_offset, c_string in list(strings_ascii(buf, n))], ['{}: {}'.format(c_offset, c_string) for c_offset, c_string in list(strings_unicode(buf, n))]
    if remove_hex:
        return [c_string for c_offset, c_string in list(strings_ascii(buf, n))], [c_string for c_offset, c_string in list(strings_unicode(buf, n))]
    return list(strings_ascii(buf, n)), list(strings_unicode(buf, n))

def get_functions(pclass):
    """
    This function find all the function inside a class.

    :param pclass: class pointer.
    :return: return a list of tuples: [(func name, func pointer), ...].
    """
    return inspect.getmembers(pclass, predicate=inspect.isfunction)

def get_func_args(func):
    """
    This function find all the function arguments.

    :param func: function pointer
    :return: tuple of tuples (variables name, variable default values(can be None))
    """
    return inspect.getargspec(func)#func.__code__.co_varnames, func.__defaults__

def loading_start(loading_reason="Loading, Please Wait"):
    """
    Start a new process with the load screen and return the proc(subprocess.Popen object) to be use later to terminate it(using loading_end function).
    :param loading_reason: the text that display in the new windows title (Loading Please Wait (loading_reason).
    :return: subprocess.Popen object
    """
    global root

    file_path = os.path.join(os.getcwd(), "volexp.py") if os.path.exists(os.path.join(os.getcwd(), "volexp.py")) else (os.path.realpath(os.path.realpath('__file__').replace('__file__', 'volexp.py')) if all_plugins[0] == 'path' else all_plugins[0])
    if not os.path.exists(file_path):
        file_path = file_path.replace(os.path.split(file_path)[1], os.path.join('volatility', 'plugins', 'volexp.py')).replace('volexp.py', os.path.join('volatility', 'plugins', 'volexp.py')).replace(os.path.join('volatility', 'plugins', 'volatility', 'plugins'), os.path.join('volatility', 'plugins'))

    cc = [sys.executable.replace(' ', ''),file_path, 'LoadScreen',loading_reason]
    sub_proc = subprocess.Popen(cc)
    root.withdraw()
    return sub_proc

def loading_end(sub_proc=None):
    """
    Kill the sub_proc (subprocess.Popen object) and display the current Tk again.
    :param sub_proc: subprocess.Popen object
    :return: None
    """
    global root
    if sub_proc:
        try:
            os.kill(sub_proc.pid, 10)
        except OSError:
            pass # The process already dead.
    root.deiconify()

def load_tp_start(self, loadint_reason="Update"):
    self.load_info = tk.Toplevel()
    self.load_info.title('Updating Table Please Wait(add user, files info)')
    self.load_info.grab_set()

def unload_tp(self):
    self.load_info.grab_release()
    self.load_info.destroy()

def get_right_member(struct, list_members):
    '''
    Return the right struct member from the list of members (to support a diffrent version).
    '''
    for item in list_members:
        items = item.split('.')
        c_struct = struct
        for sub_item in items:
            if not hasattr(c_struct, sub_item):
                break
            c_struct = getattr(c_struct, sub_item)
        else:
            return c_struct

def _from_rgb(rgb):
    '''
    Translates an rgb tuple of int to a tkinter friendly color code
    '''
    return "#%02x%02x%02x" % rgb

def create_progress_bar(title='progress'):
    '''
    Create a progress bar object
    :param title: the title
    :return: toplevel, progress_bar, the number of the current.
    '''
    popup = tk.Toplevel()
    tk.Label(popup, text=title).grid(row=0,column=0)

    progress = 0
    progress_var = tk.DoubleVar()
    progress_bar = Progressbar(popup, variable=progress_var, maximum=100)
    progress_bar.grid(row=1, column=0)
    popup.pack_slaves()
    return (popup, progress_bar, progress_var)

def start_vol(file_path, profile, command):
    '''
    Starts a volatility shell (on windows)
    :param file_path: image path
    :param profile: profile
    :param command: command (plugin)
    :return:
    '''
    os.system('start cmd /k echo {} {} -f {} --profile={} {}'.format(sys.executable, sys.argv[0], file_path, profile, command))

def run_struct_analyze(struct_type, address, app=None, pid=4, as_thread=True, write_sup=True):
    '''
    Run the struct analyze plugin
    :param struct_type: the Struct we want to analyze (example: _EPROCESS)
    :param address: the address of the struct we want to analyze
    :return: None
    '''

    # Add to job queue
    id = time.time()
    job_queue.put_alert((id, 'Struct Analyzer', '{}, args: {} ({})'.format(struct_type, address, pid), 'Running'))
    self = volself
    sa_conf = copy.deepcopy(conf.ConfObject())
    # Define conf
    sa_conf.remove_option('SAVED-FILE')
    sa_conf.remove_option('DUMP-DIR')
    sa_conf.remove_option('start')
    sa_conf.remove_option('START')
    sa_conf.optparser.set_conflict_handler("resolve")
    sa_conf.readonly = {}
    sa_conf.PROFILE = self._config.PROFILE
    sa_conf.LOCATION = self._config.LOCATION
    sa_conf.ADDR = str(hex(address)).replace('L','')
    sa_conf.STRUCT = struct_type

    if write_sup and hasattr(sa_conf, 'WRITE') and sa_conf.WRITE:
        sa_conf.WRITE = True # Enable write support
        flag = True
    else:
        flag = False

    sa_conf.PID = pid
    my_sa = StructAnalyze(sa_conf)

    # Unable to parse an object
    try:
        my_sa.calculate()
    except Exception as ex:
        print ex

    if as_thread:
        global queue
        def func_to_main(my_sa, app):
            if not app:
                app = tk.Toplevel()
                x = root.winfo_x()
                y = root.winfo_y()
                app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
                app.title("Struct Analayzer {} ({})".format(struct_type, address))
                app.geometry("950x450")
            my_sa.get_se_frame(app, flag)

        queue.put((func_to_main,(my_sa, app)))
    else:
        if not app:
            app = tk.Toplevel()
            x = root.winfo_x()
            y = root.winfo_y()
            app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
            app.title("Struct Analayzer {} ({})".format(struct_type, address))
            app.geometry("950x450")
        my_sa.get_se_frame(app, flag)

    job_queue.put_alert((id, 'Struct Analyzer', '{}, args: {} ({})'.format(struct_type, address, pid), 'Done'))

def dump_explorer_file(offset, directory=None):
    '''
    Dump a file object from the memory offset to the HD (self._config.DUMP-DIR).
    and return the data
    '''
    global volself
    global lock

    # Change to hex value (if not str).
    if not type(offset) is str:
        offset = hex(offset)

    # Remove the L (long).
    if offset.endswith('L'):
        offset = offset[:-1]

    self = volself
    def_conf = conf.ConfObject()
    # Define conf
    def_conf.remove_option('SAVED-FILE')
    def_conf.readonly = {}
    def_conf.PROFILE = self._config.PROFILE
    def_conf.LOCATION = self._config.LOCATION
    def_conf.DUMP_DIR = directory or self._config.DUMP_DIR
    def_conf.OFFSET = None
    def_conf.PID = None
    def_conf.REGEX = None
    def_conf.kaddr_space = utils.load_as(def_conf)

    # If windows 10 we need to take the physical address. (remove when mic fix this in dumpfiles plugin)
    if (def_conf.kaddr_space.profile.metadata.get("major"), def_conf.kaddr_space.profile.metadata.get("minor")) == (6, 4):
        def_conf.PHYSOFFSET = hex(def_conf.kaddr_space.vtop(int(offset, 16) if offset.startswith('0x') else int(offset))).replace('L', '')
    else:
        def_conf.PHYSOFFSET = offset

    # Resolve optparser conflicts
    def_conf.optparser.set_conflict_handler("resolve")

    # Validate parametets
    if self._config.DUMP_DIR == None:
        debug.warning("Please specify a dump directory (--dump-dir)")
        return
    elif not os.path.isdir(self._config.DUMP_DIR):
        debug.warning(self._config.DUMP_DIR + " is not a directory")
        return

    dumpfiles.debug.error = lambda e: sys.stderr.write('[-] Invalid PHYSOFFSET\n')
    df = dumpfiles.DumpFiles(def_conf)
    df_calc = df.calculate()

    file_mem = {}
    for summaryinfo in df_calc:
        file_mem[summaryinfo['type']] = ''

        if summaryinfo['type'] == "DataSectionObject":
            if not directory:
                print "DataSectionObject {0:#010x}   {1:<6} {2}\n".format(summaryinfo['fobj'], summaryinfo['pid'], summaryinfo['name'])
            if len(summaryinfo['present']) == 0:
                continue

            of = open(summaryinfo['ofpath'], 'wb')

            for mdata in summaryinfo['present']:
                rdata = None
                if not mdata[0]:
                    continue

                try:
                    rdata = def_conf.kaddr_space.base.read(mdata[0], mdata[2])
                except (IOError, OverflowError):
                    debug.debug("IOError: Pid: {0} File: {1} PhysAddr: {2} Size: {3}".format(summaryinfo['pid'], summaryinfo['name'], mdata[0], mdata[2]))

                if not rdata:
                    continue

                of.seek(mdata[1])
                of.write(rdata)

            of.close()
            time.sleep(0.01)
            of = open(summaryinfo['ofpath'], 'rb')
            file_mem[summaryinfo['type']] = of.read()

        elif summaryinfo['type'] == "ImageSectionObject":
            if not directory:
                print"ImageSectionObject {0:#010x}   {1:<6} {2}\n".format(summaryinfo['fobj'], summaryinfo['pid'], summaryinfo['name'])

            if len(summaryinfo['present']) == 0:
                continue

            of = open(summaryinfo['ofpath'], 'wb')

            for mdata in summaryinfo['present']:
                rdata = None
                if not mdata[0]:
                    continue

                try:
                    rdata = def_conf.kaddr_space.base.read(mdata[0], mdata[2])
                except (IOError, OverflowError):
                    debug.debug("IOError: Pid: {0} File: {1} PhysAddr: {2} Size: {3}".format(summaryinfo['pid'], summaryinfo['name'], mdata[0], mdata[2]))

                if not rdata:
                    continue

                of.seek(mdata[1])
                of.write(rdata)
                #file_mem[summaryinfo['type']] += rdata

            of.close()
            time.sleep(0.01)
            of = open(summaryinfo['ofpath'], 'rb')
            file_mem[summaryinfo['type']] = of.read()

        elif summaryinfo['type'] == "SharedCacheMap":
            if not directory:
                print "SharedCacheMap {0:#010x}   {1:<6} {2}\n".format(summaryinfo['fobj'], summaryinfo['pid'], summaryinfo['name'])
            of = open(summaryinfo['ofpath'], 'wb')
            for vacb in summaryinfo['vacbary']:
                if not vacb:
                    continue
                (rdata, mdata, zpad) = df.audited_read_bytes(def_conf.kaddr_space, vacb['baseaddr'], vacb['size'], True)
                ### We need to update the mdata,zpad
                if rdata:
                    try:
                        of.seek(vacb['foffset'])
                        of.write(rdata)
                        #file_mem[summaryinfo['type']] += rdata
                    except IOError:
                        # TODO: Handle things like write errors (not enough disk space, etc)
                        continue
                vacb['present'] = mdata
                vacb['pad'] = zpad

            of.close()
            time.sleep(0.01)
            of = open(summaryinfo['ofpath'], 'rb')
            file_mem[summaryinfo['type']] = of.read()

        else:
            continue
    return file_mem

def dump_pe(self, space, base, dump_file, mem=False):
    '''
    :param self: volatility self
    :param space: addr_space
    :param base: base addr
    :param dump_file: the name that the file get on the disk.
    :return: {'file': file.read()}
    '''
    global lock

    of = open(os.path.join(self._config.DUMP_DIR, dump_file), 'wb')
    pe_file = obj.Object("_IMAGE_DOS_HEADER", offset=base, vm=space)

    try:
        with lock:
            image = list(pe_file.get_image(memory=mem))
        for offset, code in image:
            of.seek(offset)
            of.write(code)
    except ZeroDivisionError:
        print 'failed'
    of.close()
    of = open(os.path.join(self._config.DUMP_DIR, dump_file), 'rb')
    file_data = of.read()
    of.close()
    #delete of
    return {'file' : file_data}

def upload_to_virus_total(file_name, file_path, apikey=None):
    '''
    Upload a file to virus total
    :param file_name: the file name
    :param file_path: the file path
    :param apikey: virustotal api key
    :return: None
    '''
    if not has_requests:
                queue.put((messagebox.showerror, ("Error", "Please download request lib\n(pip install requests)")))
                return
    elif apikey == None or apikey=='':
        def show_message_func():
            messagebox.showerror("Error", "There is no api key\nPlease go to Options->Options and enter apikey")

        queue.put((show_message_func, ()))
        return
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': apikey}
    files = {'file': (file_name, file_path)}
    response = requests.post(url, files=files, params=params)
    print response

def virus_total(hash, process_name, pid, file_path, apikey=None):
    '''
    Submit file to virus total (using hash)
    :param hash: file hash
    :param process_name: process name
    :param pid: process pid
    :param file_path: the file path
    :param apikey: virus total api key
    :return: None
    '''
    global plugins_output
    if not has_requests:
        queue.put((messagebox.showerror, ("Error", "Please download request lib\n(pip install request)")))
        return
    elif apikey == None or apikey=='':
        def show_message_func():
            messagebox.showerror("Error", "There is no API key\nPlease go to Options->Options and enter API key")

        queue.put((show_message_func, ()))
        return

    total_output = ""

    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    view_url=r'https://www.virustotal.com/gui/file/{}/detection'
    params = {'apikey': apikey,
              'resource': hash}
    try:
        response = requests.get(url, params=params)
        result = response.json()
    except requests.ConnectionError:
        debug.warning('Virus Total Failed: you are not connected to the internet/you disconnected for a momonet(try to see if there is connection problems and try again later).')
        return
    if result.has_key(u'positives'):
        positive = result[u'positives']
    else:
        print result
        positive = 0
    if result.has_key(u'total'):
        total = result[u'total']
    else:
        print 'hash not exist in virus total DB'
        if positive > 50:
            total = '{} or more'.format(positive)
        else:
            total = '50+'
    write = 'Status for the process: {} <{}/{} AV think this is a virus>(file path:{}, sha-256:{}).'.format(
        process_name, positive, total, file_path, hash)

    if not plugins_output.has_key(int(pid)):
        plugins_output[int(pid)] = []

    total_output+=write
    print write
    write = view_url.format(hash)
    total_output += '\n{}'.format(write)
    print write
    if result.has_key(u'scans'):
        for antiVirus in result[u'scans']:
            av_result = result[u'scans'][antiVirus]
            # If the antivirus found a virus on this file (process).
            if av_result[u'detected']:
                write = 'This process (-<- {} ->-) have been detect by the antivirus: {} for {}'.format(process_name,
                                                                                                        antiVirus,
                                                                                                        av_result[
                                                                                                            u'result'])
                total_output+="\n{}".format(write)
                print write

        plugins_output[int(pid)].append(("VirusTotal", total_output))
    else:
        plugins_output[int(pid)].append(("VirusTotal", 'Virus Total dont know this hash -> {} (Try to upload this file (if you want) and then check for output)'.format(hash)))
    print 'Done VirusTotal'

def get_security_descriptor(obj_header, addr_space):
    """
    This function get the security descriptor object of some object from the object header.
    :param obj_header: object header / object address
    :param addr_space: address space
    :return:
    """
    try:
        if obj_header.obj_type != '_OBJECT_HEADER':
            obj_header  = obj.Object("_OBJECT_HEADER", obj_header.obj_offset - addr_space.profile.get_obj_offset('_OBJECT_HEADER', 'Body'), addr_space)
        # 64bit uses relative security descriptors and the last 4 bits used internally by the os (so we ignore them).
        if "32bit" == addr_space.profile.metadata.get('memory_model', 0):
            sdtype = "_SECURITY_DESCRIPTOR"
            sdaddr = obj_header.SecurityDescriptor >> 3 << 3
        else:
            sdtype = "_SECURITY_DESCRIPTOR_RELATIVE"
            sdaddr = obj_header.SecurityDescriptor >> 4 << 4

        sd = obj.Object(sdtype, sdaddr, addr_space)
    except Exception as ex:
        sd = None
    return sd

def get_acl_info(acl, addr_space, obj_type):
    """
    this function return information related to access control list
    :param acl: access control list (_ACL)
    :param addr_space: address space (volatility address space object)
    :param obj_type: object type (string)
    :return: (ace_type ,[ace_flags], ace_size, (ace_sid, ace_name), [ace_mask])
    """
    current_offset = acl.obj_offset + addr_space.profile.get_obj_size('_ACL')
    for i in range(acl.AceCount):

        # Check if the ace address is invalid
        if not addr_space.is_valid_address(current_offset):
            return

        ace = obj.Object("_ACE", current_offset, addr_space)

        # Check if the ace is invalid
        if not ace:
            return

        ace_type = ace.Header.Type
        ace_flags = str(ace.Header.Flags).split(', ') if ace.Header.Flags != 0 else ['NO_INHERITANCE_SET']
        ace_size = ace.Header.Size
        ace_sid = get_sid_string(obj.Object("_SID",ace.SidStart.obj_offset, addr_space))

        if ace_sid in getsids.well_known_sids:
            ace_sid_name = str(getsids.well_known_sids[ace_sid])
        elif ace_sid in getsids.getservicesids.servicesids:
            ace_sid_name = str(getsids.getservicesids.servicesids[ace_sid])
        elif ace_sid in user_sids:
            ace_sid_name = str(user_sids[ace_sid])
        else:
            sid_name_re = getsids.find_sid_re(ace_sid, getsids.well_known_sid_re)
            if sid_name_re:
                ace_sid_name = str(sid_name_re)
            else:
                ace_sid_name = "UNKNOWN"

        if obj_type.title() not in ('Process', 'Thread', 'Token', 'Service', 'File', 'Device', 'Registry'):
            #raise ("Invalid object type incerted to get_acl_info func: {}".format(obj_type))
            # Use Generic access mask (this apply to all type of objects.
            ACCESS_MASK = {0x80000000: 'GENERIC_READ',
                           0x40000000: 'GENERIC_WRITE',
                           0x20000000: 'GENERIC_EXECUTE',
                           0x10000000: 'GENERIC_ALL',
                           0x08000000: 'RESERVED(27)',
                           0x04000000: 'RESERVED(26)',
                           0x02000000: 'ACCESS_SYSTEM_SECURITY',
                           0x01000000: 'SACL_ACCESS',
                           0x00800000: 'RESERVED(23)',
                           0x00400000: 'RESERVED(22)',
                           0x00200000: 'RESERVED(21)',
                           0x00100000: 'SYNCHRONIZE',
                           0x00080000: 'WRITE_OWNER',
                           0x00040000: 'WRITE_DAC',
                           0x00020000: 'READ_DAC',
                           0x00010000: 'DELETE'}
            ace_mask_num = int(ace.ProcessMask) # the process mask is a random choose (we take the number not the meaning flags).
            ace_mask = []
            for c_flag in ACCESS_MASK:
                if ace_mask_num & c_flag:
                    ace_mask.append(ACCESS_MASK[c_flag])
            ace_mask = ', '.join(ace_mask)

        else:
            ace_mask = str(getattr(ace, "{}Mask".format(obj_type.title())))

        yield (ace_type ,ace_flags, ace_size, (ace_sid, ace_sid_name), ace_mask)
        current_offset += ace_size

def get_sid_string(sid):
    id_auth = None
    for i in sid.IdentifierAuthority.Value:
        id_auth = i

    ## not a valid sid, currently all sid revisions == 1
    if sid.Revision != 1:
        raise TypeError

    if id_auth:
        return "S-" + "-".join(str(i) for i in (sid.Revision, id_auth) + tuple(sid.SubAuthority))
    return 'Unnable to parse sid'

def get_security_info(sd, addr_space, obj_type):
    """
    Get security information from security descriptor
    :param sd: _SECURITY_DESCRIPTOR
    :param addr_space: address space
    :param obj_type: object type
    :return: (('owner sid', 'owner name'), ('group sid', 'group name'), [dacl], [sacl])
    """
    # Make sure we have the security descriptor/relative object
    if not sd.obj_type or not '_SECURITY_DESCRIPTOR' in sd.obj_type:
        sd = get_security_descriptor(sd, addr_space)

    # Check if the security decriptor is valid.
    if not sd:
        return (('', ''), ('', ''), [], [])

    dacl = []
    sacl = []
    control_flags = []
    control_flags_num = sd.Control
    for c_flag in sd_ctrl_flags:
        if control_flags_num & c_flag:
            control_flags.append(sd_ctrl_flags[c_flag])

    # get DACL info
    if 'SE_DACL_PRESENT' not in control_flags:
        pass # no Dacl !!
    elif sd.Dacl == 0:
        pass # SE_DACL_PRESENT with null Dacl !!
    else:
        if 'SE_SELF_RELATIVE' in control_flags:
            dacl = obj.Object("_ACL", sd.obj_offset + sd.Dacl.v(), addr_space)
        else:
            #if (addr_space.profile.metadata.get('major', 0) == 6):
            #    sd = obj.Object("_SECURITY_DESCRIPTOR", sd.obj_offset, addr_space)
            dacl = obj.Object("_ACL", sd.Dacl.v(), addr_space)
        if dacl:
            dacl = list(get_acl_info(dacl, addr_space, obj_type))
        else:
            dacl = []

    # Get SACL info
    if 'SE_SACL_PRESENT' in control_flags:
        if 'SE_SELF_RELATIVE' in control_flags:
            sacl = obj.Object("_ACL", sd.obj_offset + sd.Sacl.v(), addr_space)
        else:
            sacl = obj.Object("_ACL", sd.Sacl.v(), addr_space)
        if sacl:
            sacl = list(get_acl_info(sacl, addr_space, obj_type))
        else:
            sacl= []

    # Get owner and group sids
    if 'SE_SELF_RELATIVE' in control_flags:
        owner_sid = obj.Object("_SID", sd.obj_offset + sd.Owner, addr_space)
        group_sid = obj.Object("_SID", sd.obj_offset + sd.Group, addr_space)
    else:
        group_sid = obj.Object("_SID", sd.Group, addr_space)
        owner_sid = obj.Object("_SID", sd.Owner, addr_space)

    owner_sid = get_sid_string(owner_sid)
    group_sid = get_sid_string(group_sid)

    if owner_sid in getsids.well_known_sids:
        owner_sid_name = str(getsids.well_known_sids[owner_sid])
    elif owner_sid in getsids.getservicesids.servicesids:
        owner_sid_name = str(getsids.getservicesids.servicesids[owner_sid])
    elif owner_sid in user_sids:
        owner_sid_name = str(user_sids[owner_sid])
    else:
        sid_name_re = getsids.find_sid_re(owner_sid, getsids.well_known_sid_re)
        if sid_name_re:
            owner_sid_name = str(sid_name_re)
        else:
            owner_sid_name = "UNKNOWN"

    if group_sid in getsids.well_known_sids:
        group_sid_name = str(getsids.well_known_sids[group_sid])
    elif group_sid in getsids.getservicesids.servicesids:
        group_sid_name = str(getsids.getservicesids.servicesids[group_sid])
    elif group_sid in user_sids:
        group_sid_name = str(user_sids[group_sid])
    else:
        sid_name_re = getsids.find_sid_re(group_sid, getsids.well_known_sid_re)
        if sid_name_re:
            group_sid_name = str(sid_name_re)
        else:
            group_sid_name = "UNKNOWN"

    return ((owner_sid, owner_sid_name), (group_sid, group_sid_name), dacl, sacl)

#endregion global fucntion

#region Gui:
class AutocompleteCombobox(Combobox):
    '''
    A gui class that return frame with a autocomplete combobox.
    '''
    def set_completion_list(self, completion_list):
        """Use our completion list as our drop down selection menu, arrows move through menu."""
        self._completion_list = sorted(completion_list, key=str.lower)  # Work with a sorted list
        self._hits = []
        self._hit_index = 0
        self.position = 0
        self.bind('<KeyRelease>', self.handle_keyrelease)
        self['values'] = self._completion_list  # Setup our popup menu

    def autocomplete(self, delta=0):
        """autocomplete the Combobox, delta may be 0/1/-1 to cycle through possible hits"""
        if delta:  # need to delete selection otherwise we would fix the current position
            self.delete(self.position, END)
        else:  # set position to end so selection starts where textentry ended
            self.position = len(self.get())

        # collect hits
        _hits = []
        for element in self._completion_list:
            if element.lower().startswith(self.get().lower()):  # Match case insensitively
                _hits.append(element)

        # if we have a new hit list, keep this in mind
        if _hits != self._hits:
            self._hit_index = 0
            self._hits = _hits

        # only allow cycling if we are in a known hit list
        if _hits == self._hits and self._hits:
            self._hit_index = (self._hit_index + delta) % len(self._hits)

        # now finally perform the auto completion
        if self._hits:
            self.delete(0, END)
            self.insert(0, self._hits[self._hit_index])
            self.select_range(self.position, END)

    def handle_keyrelease(self, event):
        """event handler for the keyrelease event on this widget"""
        if event.keysym == "BackSpace":
            self.delete(self.index(INSERT), END)
            self.position = self.index(END)
        if event.keysym == "Left":
            if self.position < self.index(END):  # delete the selection
                self.delete(self.position, END)
            else:
                self.position = self.position - 1  # delete one character
                self.delete(self.position, END)
        if event.keysym == "Right":
            self.position = self.index(END)  # go to end (no selection)
        if len(event.keysym) == 1:
            self.autocomplete()

class SmartChoose(tk.Toplevel):
    '''
    Gui calss to display the combobox choice from a list.
    '''
    def __init__(self, choose_list, func,  default=None, *args, **kwargs):
        tk.Toplevel.__init__(self, *args, **kwargs)
        self.choose_list = choose_list
        self.func = func
        self.select_box = AutocompleteCombobox(self, width=70)
        self.select_box.set_completion_list(self.choose_list)
        self.select_box.pack()
        self.select_box.focus_set()
        self.select_box.current(choose_list.index(default) if default else 0)
        self.select_box.pack()
        self.back_button = tk.Button(self, text="<- Save & Continue ->", command=self.Save)
        self.back_button.pack(side=tk.BOTTOM)
        self.dereference = None

    def Save(self):
        ''' Pick the user choose and call func'''
        user_choose = self.select_box.get()
        if not user_choose in self.choose_list:

            # Check if this type is support
            for choose in self.choose_list:
                if user_choose.lower() == choose.lower():
                    user_choose = choose.lower()
                    break
            else:
                print '[+] {} is not supported type try select from the combox another one (maybe its not good for this profile or you type it wrong)'.format(
                    user_choose)
                return
        self.dereference = user_choose
        self.func(self)

#region Properties
class PropertiesClass(Frame):
    '''
    This is the process properties class and this button classes display inside him:
    Image, Imports, Performance, Services, Threads, TcpIp, Security, Environment, Job.
    '''
    def __init__(self, master, menu_show='Image', selection=None, relate=None,  *args, **kwargs):
        Frame.__init__(self, master, *args, **kwargs)

        self.relate = relate or master
        self.selection = selection or main_table.tree.selection()[0]
        self.pid = int(main_table.tree.item(self.selection)['values'][main_table.text_by_item])
        self.title_font = tkFont.Font(family='Ariel', size=16, weight="bold", slant="italic")

        tabcontroller = NoteBook(self)
        self.frames = {}

        # Create all the classes (tabs in the properties).
        for F in (Image, Imports, Performance, Services, Threads, TcpIp, Security, Environment, Job):
            page_name = F.__name__
            frame = F(parent=tabcontroller, controller=self)
            self.frames[page_name] = frame
            frame.config()
            frame.grid(row=0, column=0, sticky=E+W+N+S)
            tabcontroller.add(frame, text=page_name)

        if not process_imports.has_key(int(self.pid)):
            tabcontroller.tab(1, state="disabled")

        # Add all plugins tab(volatility plugins and virustotal exstension)
        if plugins_output.has_key(self.pid):
            for item in plugins_output[self.pid]:
                page_name = item[0]
                frame = Plugin(parent=tabcontroller, controller=self, plugin_tup=item)
                self.frames[page_name] = frame
                frame.config()
                frame.grid(row=0, column=0, sticky=E+W+N+S)
                tabcontroller.add(frame, text=str(item[0]))

        tabcontroller.enable_traversal()
        tabcontroller.pack(fill=BOTH, expand=1)
        if self.frames.has_key(menu_show):
            tabcontroller.select(self.frames[menu_show])
        self.tabcontroller=tabcontroller

class Image(Frame):
    '''
    This class represent the Properties Image tab.
    '''
    def explore(self, path):
        '''
        Open Explorer in the path specified
        :param path: path to go in explorer
        :return: None
        '''
        if winobj_dict == {} or files_scan == {}:
            messagebox.showwarning('Notice', 'Still searching for the information\nPlease try again later.', parent=self)
            return
        elif not('\\' in path or '/' in path):
            messagebox.showerror('Error', 'This process path is invalid', parent=self)
            return

        # Process Envars
        if process_env_var.has_key(int(self.pid)):
            for env in process_env_var[int(self.pid)]:
                path = path.replace(env, process_env_var[int(self.pid)][env])

        # System Envars
        for c_pid in process_bases:
            if process_bases[int(c_pid)]["dlls"].has_key('csrss.exe'):
                if process_env_var.has_key(int(c_pid)):
                    for env in process_env_var[int(c_pid)]:
                        path = path.replace(env, process_env_var[int(c_pid)][env])

        if path.startswith('\\') or path.startswith('/'):
            path = path[1:]
        path = path.replace('/', '\\')
        if '\\' in path:
            path_split = path.replace('\\\\', '\\').split('\\')
        else:
            path_split = path.split('/')

        file_name = path_split[-1]
        drive = path_split[0]

        # Remove the /??/ on the starts of some path
        if drive.startswith('/??/'):
            drive = drive[4:]

        # Validate drive
        if not winobj_dict['/']['GLOBAL??'].has_key(drive):
            messagebox.showerror('Error', 'Invalid Drive: {}'.format(drive), parent=self)
            return
        device = winobj_dict['/']['GLOBAL??'][drive]['|properties|'][-2].replace('Target: ', '')
        path_split = [device] + path_split[1:-1]
        change_path = "\\".join(path_split)
        app = tk.Toplevel()
        x = self.controller.relate.winfo_x()
        y = self.controller.relate.winfo_y()
        app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))

        FileExplorer(app, dict=files_scan, headers=("File Name", "Access", "Type", "Pointer Count", "Handle Count", "Offset"),
                     searchTitle='Search For Files', path='{}\{}'.format(change_path, file_name), relate=app).pack(fill=BOTH, expand=YES,)
        app.title("Files Explorer")
        app.geometry("1400x650")

    def path_click(self, event=None):
        '''
        This function call the explore function with the path to open the explorer (self.path).
        :param event: None
        :return: None
        '''
        self.explore(self.path)

    def current_directory_click(self, event=None):
        '''
        This function call the explore function with the path to open the explorer (self.current_directory).
        :param event: None
        :return: None
        '''
        self.explore(self.current_directory)

    def save_comment(self, event=None):
        '''
        This function save the commen in the process_comments
        :param event: None
        :return: None
        '''
        global process_comments
        if event.char.lower() in string.printable:
            comment = '{}{}'.format(self.word_text.get("1.0", 'end-1c'), event.char.lower())
        else:
            comment = self.word_text.get("1.0", 'end-1c')
        process_comments[int(self.pid)] = comment

    def __init__(self, parent, controller):

        Frame.__init__(self, parent)
        self.controller = controller
        label = ttk.Label(self, text="Image", font=controller.title_font)
        label.config(anchor="center")
        label.pack(side="top", fill="x", pady=10)
        item = self.controller.selection

        # Get all the items from the table
        process, pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, intigrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc = main_table.tree.item(item)['values']
        self.pid = pid
        self.path = str(path)
        self.current_directory = str(cd)

        beuty_frame = ttk.Frame(self)
        lable_frame = ttk.LabelFrame(self, text=str(os.path.splitext(process)[0].title() if process else '???'))  # controller.title_font)
        lable_frame.pack(padx=5, pady=5, anchor="w")
        left_frame = ttk.Frame(lable_frame)

        # Create the string works only like this(not work with format for some reason).
        my_strings = [("Command Line:", str(cl)), ("User:", str(un)), ("Started:", str(createT))]

        # measure the text size
        txt_width = tkFont.Font().measure(self.path) / 7
        txt_width = txt_width if txt_width > tkFont.Font().measure(self.current_directory) else tkFont.Font().measure(self.current_directory)

        # Find the biggest square len (from the longest text len).
        for c_string in my_strings:
            c_width = tkFont.Font().measure(c_string) / 7
            if c_width > txt_width:
                txt_width = c_width
        txt_width = txt_width if txt_width < 250 else 250

        ttk.Label(left_frame, text='').pack(anchor="w")

        # Create path and button frames
        lf = ttk.Frame(left_frame)
        rf = ttk.Frame(left_frame)

        # Path button and text widget
        path_button = ttk.Button(lf, text="Path:", command=self.path_click)
        ToolTip(path_button, "Open In Explorer")
        path_button.pack(fill=tk.BOTH)
        txt_entry = ttk.Entry(rf, width=txt_width)
        txt_entry.insert(0, self.path)
        txt_entry.state(['readonly'])
        txt_entry.pack(anchor="w", ipady=1, pady=1)

        # Current Directory button and txt widget
        dir_button = ttk.Button(lf, text="Current Directory:", command=self.current_directory_click)
        ToolTip(dir_button, "Open In Explorer")
        dir_button.pack(anchor="w")
        txt_entry = ttk.Entry(rf, width=txt_width)
        txt_entry.insert(0, self.current_directory)
        txt_entry.state(['readonly'])
        txt_entry.pack(anchor="w", ipady=1, pady=1)
        ttk.Label(left_frame, text='\n').pack(anchor="w")

        # Pack path and button frames
        lf.pack(side=LEFT)
        rf.pack(side=LEFT)

        # Create right and left frames
        left_frame2 = ttk.Frame(lable_frame)
        tlf = ttk.Frame(left_frame2)
        trf = ttk.Frame(left_frame2)

        # Create all the labels inside the my_strings list of tuples
        for my_string in my_strings:
            label_txt = my_string[0]
            entry_txt = my_string[1]

            my_label = ttk.Label(tlf, text=label_txt, wraplength=500, width=path_button['width'])
            my_label.pack(anchor='w')
            txt_entry = ttk.Entry(trf, width=(txt_width if txt_width < 250 else 250))
            txt_entry.insert(0, entry_txt)
            txt_entry.state(['readonly'])
            txt_entry.pack(anchor='w')

        # Pack the frame
        tlf.pack(side=LEFT, ipadx=5, padx=5)
        trf.pack(side=LEFT)
        left_frame.pack(anchor="nw")
        ttk.Label(left_frame, text='\n').pack(anchor="w")
        left_frame2.pack(anchor="nw")
        #ttk.Label(self, text='\n').pack(anchor="w")

        additional_info = ''
        # Check if we have description and display it.
        if str(Description).replace(' ', ''):
            additional_info = "Description: {}".format(str(Description))

        # Check if we have company name and display it
        if str(cn).replace(' ', ''):
            additional_info = "{}\nCompany Name: {}".format(additional_info, str(cn))

        # Check if we have file version and display it
        if str(version).replace(' ', ''):
            additional_info = '{}\nVersion: {}'.format(additional_info, (str(version)))

        if additional_info != '':
            label_frame = ttk.LabelFrame(beuty_frame, text='Additional Information')
            label_frame.pack(padx=5, pady=5, anchor="w")
            _frame = ttk.Frame(label_frame)
            for c_string in additional_info.splitlines():
                my_label = ttk.Label(_frame, text=str(c_string))
                my_label.pack(anchor="w")
            _frame.pack(anchor="nw")
        beuty_frame.pack(padx=5, pady=5, fill=tk.BOTH)



        # Create the comment scrolledtext
        self.word_text = scrolledtext.ScrolledText(self, undo=True)
        self.word_text.pack(fill='both', padx=10, pady=2)
        self.word_text.insert("1.0",process_comments[int(pid)])
        self.word_text.bind('<KeyPress>', self.save_comment)

class Imports(Frame):
    '''
    This class represent the Properties Imports tab.
    '''
    def __init__(self, parent, controller):
        global process_imports

        Frame.__init__(self, parent)
        self.controller = controller
        label = ttk.Label(self, text="Imports", font=controller.title_font)
        label.config(anchor="center")
        label.pack(side="top", fill="x", pady=10)
        data = []
        headers = ('function', 'module', 'address', 'hint' )#("IAT", "Call", "Module", "Function")

        # Create the imports table if the impscan plugin is done for this process.
        if process_imports.has_key(int(self.controller.pid)):
            for iat, call, mod, func in process_imports[int(self.controller.pid)]:
                data.append((iat, call, mod, func))
            imp_treetable = TreeTable(self, headers=headers, data=data)
            imp_treetable.tree['height'] = 22 if 22 < len(data) else len(data)
            imp_treetable.pack(expand=YES, fill=BOTH)

class Performance(Frame):
    '''
    This class represent the Properties Performance tab.
    '''
    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        label = ttk.Label(self, text="Performance", font=controller.title_font)
        label.config(anchor="center")
        label.pack(side="top", fill="x", pady=10)

        priority, kt, ut, total_time, cycles, pb, ppb, virtual, page_fault, pfd, mo, ws, wsp, ws2, wss, pws, iopriority, reads, readelta, rbd, writes, writed, writebd, other, othered, otherebd, handles, peakh, gdih, userh = [str(item) for item in process_performance[self.controller.pid]]

        left_frame = ttk.Frame(self)
        right_frame = ttk.Frame(self)
        frame_size = 20


        # CPU
        label_frame = ttk.LabelFrame(left_frame, text='CPU')
        label_frame.pack(fill=tk.BOTH, padx=7, pady=7)
        my_frame = ttk.Frame(label_frame)
        cpu_info = '\n'.join(('Priority:', 'Kernel Time:', 'User Time:', 'Total Time:', 'Cycles:'))
        cpu_label = ttk.Label(my_frame, text=cpu_info, wraplength=500)
        cpu_label.pack(side=tk.LEFT)
        cpu_info = '\n'.join((priority, kt, ut, total_time, cycles))
        cpu_label = ttk.Label(my_frame, text=cpu_info, wraplength=500)
        cpu_label.pack(side=tk.RIGHT)
        my_frame.pack(fill=tk.BOTH)


        # Virtual Memory
        label_frame = ttk.LabelFrame(left_frame, text='Virtual Memory')
        label_frame.pack(fill=tk.BOTH, padx=5, pady=5)
        my_frame = ttk.Frame(label_frame)
        vm_info = '\n'.join(('Private Bytes:', 'Peak Private Bytes:', 'Virtual:', 'Page Faults:'))
        vm_label = ttk.Label(my_frame, text=vm_info, wraplength=500)
        vm_label.pack(side=tk.LEFT)
        vm_info = '{}\n{}'.format(' K\n'.join((pb, ppb, virtual)),  page_fault)
        vm_label = ttk.Label(my_frame, text=vm_info, wraplength=500)
        vm_label.pack(side=tk.RIGHT)
        my_frame.pack(fill=tk.BOTH)

        # Physical Memory
        label_frame = ttk.LabelFrame(left_frame, text='Physical Memory')
        label_frame.pack(fill=tk.BOTH, padx=5, pady=5)
        my_frame = ttk.Frame(label_frame)
        pm_info = '\n'.join(('Memory Priority:', 'Working Set:', 'WS Private:', 'WS:', 'WS Shared:', 'Peak Working Set:'))
        pm_label = ttk.Label(my_frame, text=pm_info, wraplength=500)
        pm_label.pack(side=tk.LEFT)
        pm_info = '{}\n{}'.format(mo, ' K\n'.join((ws, wsp, ws2, wss, pws)))
        pm_label = ttk.Label(my_frame, text=pm_info, wraplength=500)
        pm_label.pack(side=tk.RIGHT)
        my_frame.pack(fill=tk.BOTH)

        # I/O
        label_frame = ttk.LabelFrame(right_frame, text='I/O')
        label_frame.pack(fill=tk.BOTH, padx=5, pady=5)
        my_frame = ttk.Frame(label_frame)
        io_info = '\n'.join(('I/O Priority:', 'Reads:', 'Read Delta:', 'Read Bytes Delta:', 'Writes:', 'Write Delta:', 'Write Bytes Delta:', 'Other:', 'Other Delta:', 'Other Bytes Delta:'))
        io_label = ttk.Label(my_frame, text=io_info, wraplength=500)
        io_label.pack(side=tk.LEFT)
        io_info = '\n'.join((iopriority, reads, readelta, rbd, writes, writed, writebd, other, othered, otherebd))
        io_label = ttk.Label(my_frame, text=io_info, wraplength=500)
        io_label.pack(side=tk.RIGHT)
        my_frame.pack(fill=tk.BOTH)

        # Handles
        label_frame = ttk.LabelFrame(right_frame, text='Handles')
        label_frame.pack(fill=tk.BOTH, padx=5, pady=5)
        my_frame = ttk.Frame(label_frame)
        handles_info = '\n'.join(('Handles:', 'Peak Handles:', 'GDI Handles:', 'USER Handles:'))
        handle_label = ttk.Label(my_frame, text=handles_info, wraplength=500)
        handle_label.pack(side=tk.LEFT)
        handles_info = '\n'.join((handles, peakh, gdih, userh))
        handle_label = ttk.Label(my_frame, text=handles_info, wraplength=500)
        handle_label.pack(side=tk.RIGHT)
        my_frame.pack(fill=tk.BOTH)

        # Pack the frames.
        left_frame.pack(side=LEFT, anchor="nw")
        right_frame.pack(side=LEFT, anchor="nw")

class Services(Frame):
    '''
    This class represent the Properties Service tab.
    '''
    def __init__(self, parent, controller):
        global service_dict
        Frame.__init__(self, parent)
        self.controller = controller
        label = ttk.Label(self, text="Services", font=controller.title_font)
        label.config(anchor="center")
        label.pack(side="top", fill="x", pady=10)
        data = []

        # Get the data for the table (if there is any).
        if service_dict.has_key(self.controller.pid):
            for svc in service_dict[self.controller.pid]:
                data.append(svc)

        # Create and pack the table.
        self.svc_treetable = TreeLable(self, headers=('offset', 'order', 'start', 'pid', 'service name', 'display name', 'type', 'state', 'binary'), data=data, display=('service name', 'display name', 'state'))

class Threads(Frame):
    '''
    This class represent the Properties Threads tab.
    '''
    def __init__(self, parent, controller):
        global lock
        Frame.__init__(self, parent)
        self.controller = controller
        item = self.controller.selection

        # Check if we cant get this process eprocess structure (then it in the title and return).
        if not main_table.tree.item(item)['values'][-1]:
            label = ttk.Label(self, text="Unable to find _EPROCESS struct of this process..", font=controller.title_font)
            label.config(anchor="center")
            label.pack(side="top", fill="x", pady=10)
            return

        label = ttk.Label(self, text="Threads", font=controller.title_font)
        label.config(anchor="center")
        label.pack(side="top", fill="x", pady=10)
        data = []
        thread_flags = {0: "Terminate", 1: "Dead", 2: "Hide from debug", 3: "Impersonating", 4: "System", 5: "Hard Error Disable", 6: "Break On Termination", 7: "Skip Creation Message", 8: "Skip Terminate Message"}
        self.proc = process_bases[self.controller.pid]["proc"]

        # Get the process threads data
        if process_threads.has_key(int(self.controller.pid)):
            data = process_threads[int(self.controller.pid)].values()

        # Create the threads table
        self.thread_treetable = TreeLable(self, headers=("Tid", "Start Addr", "Flag", "Stack Base", "Base Priority", "Priority", "User Time", "Kernel Time", "Create Time", "Offset"), data=data, display=('Tid', 'Flag', 'Create Time'))
        self.thread_treetable.tree['height'] = 7 if len(data) > 7 else len(data)

        # Add the HexDump and StructAnalysis options
        self.thread_treetable.aMenu.add_command(label='HexDump', command=lambda: self.viewHexDump(0))
        self.thread_treetable.aMenu.add_command(label='Struct Analysis ', command=self.run_struct_analyze)
        self.thread_treetable.tree.bind("<Return>", self.viewHexDump)
        self.thread_treetable.tree.bind("<Double-1>", self.OnDoubleClick)

    def viewHexDump(self, event):
        '''
        This function display the hexdump of the thread start address.
        :param event: None
        :return: None
        '''
        global volself
        global lock
        item = self.thread_treetable.tree.selection()[0]
        start_addr = self.thread_treetable.tree.item(item)['values'][1]

        # Get the dissasemble data of this thread start address (only after we get the lock).
        with lock:

            hex_dis = volself.disassemble(self.proc.get_process_address_space(), start_addr if type(start_addr) is not str else (start_addr.strip('L')))

        # Create and config the Toplevel
        app = tk.Toplevel()
        x = self.controller.relate.winfo_x()
        y = self.controller.relate.winfo_y()
        app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
        app.title('Disasmble | HexDump')
        app.geometry("600x350")
        pw = PanedWindow(app, orient='vertical')

        hex = []

        # Get the hex data of this thread start address.
        for i in range(len(hex_dis[0].splitlines())):
            hex.append(tuple(hex_dis[0].splitlines()[i].split('  ')))

        # Create the tables
        dis_tree = TreeTable(pw, headers=('Address', 'OP', 'Disasmble'), data=hex_dis[1].splitlines())
        hex_tree = TreeTable(pw, headers=('Address', "Hex", "Dump"), data=hex, resize=True)
        hex_tree.tree['height'] = 7
        pw.add(dis_tree)
        pw.add(hex_tree)
        hex_tree.pack(expand=YES, fill=BOTH)
        dis_tree.pack(expand=YES, fill=BOTH)
        pw.pack(expand=YES, fill=BOTH)

    def OnDoubleClick(self, event):
        '''
        Double click handles (display hex dump)
        :param event: None
        :return: None
        '''

        # Double click on table header to resize
        if event and event.y < 25 and event.y > 0:
            try:
                if self.thread_treetable.tree.identify_region(event.x, event.y) == 'separator':
                    self.thread_treetable.resize_col(self.thread_treetable.tree.identify_column(event.x))
                return
            except tk.TclError:
                return
        # Double click where no item selected
        elif len(self.thread_treetable.tree.selection()) == 0 :
            return

        self.viewHexDump(event)

    def run_struct_analyze(self, struct_type="_ETHREAD"):
        '''
        get address and sent to teal struct analyze function.
        '''
        item = self.thread_treetable.tree.selection()[0]
        addr = self.thread_treetable.tree.item(item)['values'][-1]

        # Check if the address is None and if so then return.
        if not addr:
            print "unable to find the address of this {}".format(struct_type)
            return

        print "Run Struct Analyze on {}, addr: {}".format(struct_type, addr)
        threading.Thread(target=run_struct_analyze, args=(struct_type, addr)).start()

class TcpIp(Frame):
    '''
    This class represent the Properties TcpIp tab.
    '''
    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        label = ttk.Label(self, text="TcpIp", font=controller.title_font)
        label.config(anchor="center")
        label.pack(side="top", fill="x", pady=10)

        # Get the connections data
        data = [ tup for tup in process_connections[self.controller.pid]] if process_connections.has_key(self.controller.pid) else [("There", "is", "no", "conenctions", "at", "all") if len(process_connections) > 0 else ["searching", "for", "connections,", "try", "again", "later"]]

        # Create the connections table.
        env_treetable = TreeTable(self, headers=("Pid", "Protocol", "Local Address", "Remote Address", "State", "Created", "Offset"), data=data, display=("Protocol", "Local Address", "Remote Address", "State", "Created"))
        env_treetable.tree['height'] = 22 if 22 < len(data) else len(data)
        env_treetable.pack(expand=YES, fill=BOTH)

class Security(Frame):
    '''
    This class represent the Properties Security tab.
    '''
    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        label = ttk.Label(self, text="Security", font=controller.title_font)
        label.config(anchor="center")
        label.pack(side="top", fill="x", pady=10)
        self.pw = PanedWindow(self, orient='vertical')
        item = self.controller.selection
        process, pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, intigrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc = main_table.tree.item(item)['values']
        proc_token, token_user, token_session, token_session_id, token_elevated, token_virtualized, token_protected = "", "", "", "", "", "", ""

        # Get the token information if that information present in the dictionary.
        if process_token.has_key(int(pid)):
            proc_token, token_user, token_session, token_session_id, token_elevated, token_virtualized, token_protected = process_token[int(pid)]

        protection = str(protection)
        c_sid = ''

        # Get the user sid.
        if process_security[self.controller.pid].has_key('Groups'):

            # Windows 10 problem.
            if len(process_security[self.controller.pid]['Groups']) and len(process_security[self.controller.pid]['Groups'][0]):
                c_sid = process_security[self.controller.pid]['Groups'][0][1]

        my_info = ''.join(('User: ', token_user or '', '\nSID: ', c_sid or '', '\nSession: ', str(token_session_id), '\tLogon Session: ', token_session, '\nVirtualized: ', token_virtualized, '\tProtected: ', protection, '\n'))
        lb_info = ttk.Label(self, text=my_info, wraplength=500)#, background="white")
        lb_info.pack()

        # Get the Groups security information (if we have it).
        if process_security[pid].has_key('Groups'):
            data = process_security[pid]['Groups']
            group_treetable = TreeTable(self.pw, headers=("Group", "SIDs", "Flags"), data=data, resize=True)
            group_treetable.tree['height'] = 7 if 7 < len(data) else len(data)
            group_treetable.pack(expand=YES, fill=BOTH)
            self.pw.add(group_treetable)

        # Get the Privs security information (if we have it).
        if process_security[pid].has_key('Privs'):
            data = process_security[pid]['Privs']
            privs_treetable = TreeTable(self.pw, headers=("Num","Privileges","Flags","Help"), data=data, resize=True)
            privs_treetable.tree['height'] = 10 if 10 < len(data) else len(data)
            privs_treetable.pack(expand=YES, fill=BOTH)
            self.pw.add(privs_treetable)

        # Pack the information.
        self.pw.pack(fill=BOTH, expand=YES)#(side=TOP, fill=BOTH)

class Environment(Frame):
    '''
    This class represent the Properties Environment tab.
    '''
    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        label = ttk.Label(self, text="Environment", font=controller.title_font)
        label.config(anchor="center")
        label.pack(side="top", fill="x", pady=10)

        # Get the environment data
        data = [(tup, process_env_var[self.controller.pid][tup]) for tup in process_env_var[self.controller.pid]] if process_env_var.has_key(self.controller.pid) else []

        # Create the environment table
        env_treetable = TreeTable(self, headers=("Variable","Value"), data=data)
        env_treetable.tree['height'] = 22 if 22 < len(data) else len(data)
        env_treetable.pack(expand=YES, fill=BOTH)

class Job(Frame):
    '''
    This class represent the Properties Job tab.
    '''
    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        item = self.controller.selection
        if not main_table.tree.item(item)['values'][-1]:
            label = ttk.Label(self, text="Unable to find _EPROCESS struct of this process..", font=controller.title_font)
            label.config(anchor="center")
            label.pack(side="top", fill="x", pady=10)
            return
        label = ttk.Label(self, text="Job", font=controller.title_font)
        label.config(anchor="center")
        label.pack(side="top", fill="x", pady=10)
        e_proc = process_bases[self.controller.pid]["proc"]
        data = []

        # Walk over the Jobs and insert the data to the data list.
        job = e_proc.Job.dereference()
        if job:
            for task in job.ProcessListHead.list_of_type("_EPROCESS", "JobLinks"):
                data.append((task.Peb.ProcessParameters.ImagePathName.v().encode("utf8", "replace"), task.UniqueProcessId, task.InheritedFromUniqueProcessId))

        # Create the job table
        job_treetable = TreeTable(self, headers=("Process path","Pid", "Ppid"), data=data)
        job_treetable.tree['height'] = 22 if 22 < len(data) else len(data)
        job_treetable.pack(expand=YES, fill=BOTH)

class Plugin(Frame):
    '''
    This class represent the Properties <PluginName> tab.
    '''
    def __init__(self, parent, controller, plugin_tup):
        Frame.__init__(self, parent)
        self.controller = controller
        item = self.controller.selection
        label = ttk.Label(self, text=plugin_tup[0].title(), font=controller.title_font)
        label.config(anchor="center")
        label.pack(side="top", fill="x", pady=10)
        data = []

        # Get the plugin result data
        for line in plugin_tup[1].splitlines():
            data.append((line,))

        # Create the plugin table
        plugin_treetable = TreeTable(self, headers=("Result",), data=data)
        plugin_treetable.tree['height'] = 22 if 22 < len(data) else len(data)
        plugin_treetable.pack(expand=YES, fill=BOTH)


#endregion properties

#region PEProperties
class PEPropertiesClass(Frame):
    '''
    This is the dll properties class and this button classes display inside him:
    DllImage, DllImports, DllExports, MemStrings, ImageStrings
    '''
    def __init__(self, master, file_info, menu_show='PEImage', relate=None, *args, **kwargs):
        Frame.__init__(self, master, *args, **kwargs)
        self.title_font = tkFont.Font(family='Helvetica', size=16, weight="bold", slant="italic")
        self.relate = relate
        tabcontroller = NoteBook(self)
        self.frames = {}
        self.lock = threading.Lock()

        # Get all the information from the args.
        self.pefile = file_info[0]
        self.imports = file_info[1]
        self.exports = file_info[2]
        self.mem_strings = file_info[3]
        self.image_strings = file_info[4]
        self.my_dll = file_info[5]
        self.pid = file_info[6]
        self.nt_header = file_info[7]

        # If the user want to view strings
        if self.mem_strings:
            my_classes = (PEImage, PEImports, PEExports, MemStrings, ImageStrings)
        else:
            my_classes = (PEImage, PEImports, PEExports)

        # __init__ all the classes (the notebook tabs).
        for F in my_classes: #Strings
            page_name = F.__name__
            frame = F(parent=tabcontroller, controller=self)
            self.frames[page_name] = frame
            frame.config()
            frame.grid(row=0, column=0, sticky=E+W+N+S)
            tabcontroller.add(frame, text=page_name)

        tabcontroller.enable_traversal()
        tabcontroller.pack(fill=BOTH, expand=1)
        if self.frames.has_key(menu_show):
            tabcontroller.select(self.frames[menu_show])
        self.tabcontroller=tabcontroller

class PEImage(Frame):

    # _IMAGE_FILE_HEADER.Characteristics
    Characteristics = {
        'IMAGE_FILE_RELOCS_STRIPPED':         0x0001,  # Relocation info stripped from file.
        'IMAGE_FILE_EXECUTABLE_IMAGE':        0x0002,  # File is executable  (i.e. no unresolved external references).
        'IMAGE_FILE_LINE_NUMS_STRIPPED':      0x0004,  # Line nunbers stripped from file.
        'IMAGE_FILE_LOCAL_SYMS_STRIPPED':     0x0008,  # Local symbols stripped from file.
        'IMAGE_FILE_AGGRESIVE_WS_TRIM':       0x0010,  # Aggressively trim working set
        'IMAGE_FILE_LARGE_ADDRESS_AWARE':     0x0020,  # App can handle >2gb addresses
        'IMAGE_FILE_BYTES_REVERSED_LO':       0x0080,  # Bytes of machine word are reversed.
        'IMAGE_FILE_32BIT_MACHINE':           0x0100,  # 32 bit word machine.
        'IMAGE_FILE_DEBUG_STRIPPED':          0x0200,  # Debugging info stripped from file in .DBG file
        'IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP': 0x0400,
        # If Image is on removable media, copy and run from the swap file.
        'IMAGE_FILE_NET_RUN_FROM_SWAP':       0x0800,  # If Image is on Net, copy and run from the swap file.
        'IMAGE_FILE_SYSTEM':                  0x1000,  # System File.
        'IMAGE_FILE_DLL':                     0x2000,  # File is a DLL.
        'IMAGE_FILE_UP_SYSTEM_ONLY':          0x4000,  # File should only be run on a UP machine
        'IMAGE_FILE_BYTES_REVERSED_HI':       0x8000,  # Bytes of machine word are reversed.
    }

    # _IMAGE_FILE_HEADER._IMAGE_OPTIONAL_HEADER.DllCharacteristics &
    DllCharacteristics = {
        'IMAGE_LIBRARY_PROCESS_TERM':                     0x0002,  # Reserved.
        'IMAGE_LIBRARY_PROCESS_INIT':                     0x0001,  # Reserved.
        'IMAGE_LIBRARY_THREAD_INIT':                      0x0004,  # Reserved.
        'IMAGE_LIBRARY_THREAD_TERM':                      0x0008,  # Reserved.
        'IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA':       0x0020,
        # Image can handle a high entropy 64-bit virtual address space.
        'IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE':          0x0040,  # DLL can move.
        'IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY':       0x0080,  # Code Integrity Image
        'IMAGE_DLLCHARACTERISTICS_NX_COMPAT':             0x0100,  # Image is NX compatible
        'IMAGE_DLLCHARACTERISTICS_NO_ISOLATION':          0x0200,  # Image understands isolation and doesn't want it
        'IMAGE_DLLCHARACTERISTICS_NO_SEH':                0x0400,  # Image does not use SEH.  No SE handler may reside in this image
        'IMAGE_DLLCHARACTERISTICS_NO_BIND':               0x0800,  # Do not bind this image.
        'IMAGE_DLLCHARACTERISTICS_APPCONTAINER':          0x1000,  # Image should execute in an AppContainer
        'IMAGE_DLLCHARACTERISTICS_WDM_DRIVER':            0x2000,  # Driver uses WDM model
        'IMAGE_DLLCHARACTERISTICS_GUARD_CF':              0x4000,  # Image supports Control Flow Guard.
        'IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE': 0x8000,
    }

    # subsystem (_IMAGE_FILE_HEADER._IMAGE_OPTIONAL_HEADER.Subsystem)
    Subsystem = [
        'IMAGE_SUBSYSTEM_UNKNOWN',         # Unknown subsystem.
        'IMAGE_SUBSYSTEM_NATIVE',          # Image doesn't require a subsystem.
        'IMAGE_SUBSYSTEM_WINDOWS_GUI',     # Image runs in the Windows GUI subsystem.
        'IMAGE_SUBSYSTEM_WINDOWS_CUI',     # Image runs in the Windows character subsystem.
        'IMAGE_SUBSYSTEM_OS2_CUI',         # image runs in the OS/2 character subsystem.
        'IMAGE_SUBSYSTEM_POSIX_CUI',       # image runs in the Posix character subsystem.
        'IMAGE_SUBSYSTEM_NATIVE_WINDOWS',  # image is a native Win9x driver.
        'IMAGE_SUBSYSTEM_WINDOWS_CE_GUI',  # Image runs in the Windows CE subsystem.
        'IMAGE_SUBSYSTEM_EFI_APPLICATION',
        'IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER',
        'IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER',
        'IMAGE_SUBSYSTEM_EFI_ROM',
        'IMAGE_SUBSYSTEM_XBOX',
        'IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION',
        'IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG'
    ]

    # _IMAGE_SECTION_HEADER.Characteristics
    SHCharacteristics = {
        'IMAGE_SCN_LNK_NRELOC_OVFL' : 0x01000000,  # Section contains extended relocations.
        'IMAGE_SCN_MEM_DISCARDABLE' : 0x02000000,  # Section can be discarded.
        'IMAGE_SCN_MEM_NOT_CACHED'  : 0x04000000,  # Section is not cachable.
        'IMAGE_SCN_MEM_NOT_PAGED'   : 0x08000000,  # Section is not pageable.
        'IMAGE_SCN_MEM_SHARED'	    : 0x10000000,  # Section is shareable.
        'IMAGE_SCN_MEM_EXECUTE'		: 0x20000000,  # Section is executable.
        'IMAGE_SCN_MEM_READ'		: 0x40000000,  # Section is readable.
        'IMAGE_SCN_MEM_WRITE'		: 0x80000000}  # Section is writeable.


    def explore(self, path):
        '''
        Open Explorer in the path specified
        :param path: path to go in explorer
        :return: None
        '''
        if winobj_dict == {} or files_scan == {}:
            messagebox.showwarning('Notice', 'Still searching for the information\nPlease try again later.', parent=self)
            return
        elif not('\\' in path or '/' in path):
            messagebox.showerror('Error', 'This path is invalid', parent=self)
            return

        # Process Envars
        if process_env_var.has_key(int(self.pid)):
            for env in process_env_var[int(self.pid)]:
                path = path.replace(env, process_env_var[int(self.pid)][env])

        # System Envars
        for c_pid in process_bases:
            if process_bases[int(c_pid)]["dlls"].has_key('csrss.exe'):
                if process_env_var.has_key(int(c_pid)):
                    for env in process_env_var[int(c_pid)]:
                        path = path.replace(env, process_env_var[int(c_pid)][env])

        path = path.replace('/', '\\')
        if path.startswith('\\') or path.startswith('/'):
            path = path[1:]
        if '\\' in path:
            path_split = path.replace('\\\\', '\\').split('\\')
        else:
            path_split = path.split('/')

        file_name = path_split[-1]
        drive = path_split[0]

        # Remove the /??/ on the starts of some path
        if drive.startswith('/??/'):
            drive = drive[4:]

        # Validate drive
        if not winobj_dict['/']['GLOBAL??'].has_key(drive):
            messagebox.showerror('Error', 'Invalid Drive: {}'.format(drive), parent=self)
            return

        device = winobj_dict['/']['GLOBAL??'][drive]['|properties|'][-2].replace('Target: ', '')
        path_split = [device] + path_split[1:-1]
        change_path = "\\".join(path_split)
        app = tk.Toplevel()
        x = self.controller.relate.winfo_x()
        y = self.controller.relate.winfo_y()
        app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
        print change_path, file_name
        FileExplorer(app, dict=files_scan, headers=("File Name", "Access", "Type", "Pointer Count", "Handle Count", "Offset"),
                     searchTitle='Search For Files', path='{}\{}'.format(change_path, file_name), relate=app).pack(fill=BOTH, expand=YES,)
        app.title("Files Explorer")
        app.geometry("1400x650")

    def path_click(self, event=None):
        '''
        This function call the explore function with the path to open the explorer (self.path)
        :param event: None
        :return: None
        '''
        self.explore(self.path)

    def save_comment(self, event=None):
        '''
        This function save the commen in the pe_comments
        :param event: None
        :return: None
        '''
        global pe_comments
        if event.char.lower() in string.printable:
            comment = '{}{}'.format(self.word_text.get("1.0", 'end-1c'), event.char.lower())
        else:
            comment = self.word_text.get("1.0", 'end-1c')
        pe_comments['pid'][int(self.pid)][str(self.path)][0] = comment

    def apply_all_process(self, event=None):
        '''
        This function apply the spesified coment to all the same pe files load to other processes,
        feature to apply color as well if the user wants to (apply_all process button callback).
        :param event: None
        :return: None
        '''
        ans = messagebox.askyesnocancel("Notice", "If you press yes you will override all the other comments for this file in other processes\nPress no to append the current comment to this file in other processes\nPress cancel to return", parent=self)
        comment = self.word_text.get("1.0", 'end-1c')
        if ans == None:
            return
        elif ans:
            ans = messagebox.askquestion('Notice','Do you want to apply the color as well?', parent=self) if pe_comments['pid'][self.pid][str(self.path)][1] != 'white' else 'no'
            for pid in pe_comments['pid']:
                if pe_comments['pid'][pid].has_key(str(self.path)):
                    pe_comments['pid'][pid][str(self.path)][0] = comment
                    if ans == 'yes':
                        pe_comments['pid'][pid][str(self.path)][1] = pe_comments['pid'][self.pid][str(self.path)][1]
        else:
            ans = messagebox.askquestion('Notice','Do you to apply the color as well?', parent=self) if pe_comments['pid'][self.pid][str(self.path)][1] != 'white' else 'no'
            for pid in pe_comments['pid']:
                if pe_comments['pid'][pid].has_key(str(self.path)):
                    if int(pid) != int(self.pid):
                        pe_comments['pid'][pid][str(self.path)][0] += comment
                        if ans == 'yes':
                            pe_comments['pid'][pid][str(self.path)][1] = pe_comments['pid'][self.pid][str(self.path)][1]

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = self.parent = controller
        label = tk.Label(self, text="Image", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)
        self.pid = self.controller.pid
        left_frame = ttk.Frame(self)

        image_size = self.parent.nt_header.OptionalHeader.SizeOfImage
        image_base = self.parent.nt_header.OptionalHeader.ImageBase
        self.path = path = self.parent.my_dll.FullDllName
        subsystem = PEImage.Subsystem[int(self.parent.nt_header.OptionalHeader.Subsystem)]
        dll_characteristics = self.parent.nt_header.OptionalHeader.DllCharacteristics
        time_date_stamp = self.parent.nt_header.FileHeader.TimeDateStamp
        characteristics = self.parent.nt_header.FileHeader.Characteristics
        txt_width = tkFont.Font().measure(self.path) / 7

        # Get Characteristics
        characteristics_str = ""
        for i in PEImage.Characteristics:
            if characteristics & PEImage.Characteristics[i]:
                characteristics_str = "{} | {}".format(characteristics_str, i) if characteristics_str != "" else i

        # Get dll characteristics
        dll_characteristics_str = ""
        for i in PEImage.DllCharacteristics:
            if dll_characteristics & PEImage.DllCharacteristics[i]:
                dll_characteristics_str = "{} | {}".format(dll_characteristics_str, i) if dll_characteristics_str != "" else i

        my_strings = [  # ("Path:", str(path)),
            ("Time Stamp:\t\t", str(time_date_stamp)),
            ("Characteristics:\t\t", str(characteristics_str)),
            ("Dll Characteristics: ", str(dll_characteristics_str)),
            ("Subsystem:\t\t", str(subsystem))]

        # Find the biggest square len.
        for c_string in my_strings:
            c_width = tkFont.Font().measure(c_string) / 7
            if c_width > txt_width:
                txt_width = c_width
        txt_width = txt_width if txt_width < 250 else 250

        # Path button and text widget
        path_frame = ttk.Frame(left_frame)
        path_button = ttk.Button(path_frame, text="Path:\t\t\t", command=self.path_click)
        ToolTip(path_button, "Open In Explorer")
        path_button.pack(side=LEFT)
        self.path = str(path)
        #txt_width = tkFont.Font().measure(self.path) / 7
        txt_entry = ttk.Entry(path_frame, width=txt_width)
        txt_entry.insert(0, self.path)
        txt_entry.state(['readonly'])
        txt_entry.pack(side=LEFT, ipady=1, pady=1)
        path_frame.pack(anchor="w")
        ttk.Label(left_frame, text='').pack(anchor="w")

        # Make the lables allinged well.
        lf = ttk.Frame(left_frame)
        rf = ttk.Frame(left_frame)

        for my_string in my_strings:
            label_txt = my_string[0]
            entry_txt = my_string[1]

            my_label = ttk.Label(lf, text=label_txt, wraplength=500)
            my_label.pack(anchor="w")
            txt_entry = ttk.Entry(rf, width=txt_width)
            txt_entry.insert(0, entry_txt)
            txt_entry.state(['readonly'])
            txt_entry.pack(anchor="w")

        lf.pack(side=LEFT, ipadx=2, padx=2)
        rf.pack(side=LEFT)
        left_frame.pack(anchor="nw")
        data = []
        for c_mod in self.parent.nt_header.get_sections():
            sh_characteristics = c_mod.Characteristics
            sh_characteristics_str = ""
            for i in PEImage.SHCharacteristics:
                if sh_characteristics & PEImage.SHCharacteristics[i]:
                    sh_characteristics_str = "{} | {}".format(sh_characteristics_str,i) if sh_characteristics_str != "" else i

            data.append((str(c_mod.Name), c_mod.Misc, c_mod.VirtualAddress, c_mod.SizeOfRawData, c_mod.PointerToRawData, c_mod.PointerToRelocations, c_mod.PointerToLinenumbers, c_mod.NumberOfRelocations, c_mod.NumberOfLinenumbers, c_mod.Characteristics, sh_characteristics_str))
        headers = ("Name", "Misc", "VA", "Size Of Raw Data", "Pointer To Raw Data", "Pointer To Relocation", "Pointer To Line Numbers", "Number Of Relocation", "Number Of Line Numbers", "Characteristics", "Meaning (Characteristics)")
        display_headers = ("Name", "Misc", "VA", "Size Of Raw Data", "Pointer To Raw Data", "Characteristics", "Meaning (Characteristics)")
        section_treetable = TreeTable(self, headers=headers, data=data, display=display_headers)
        section_treetable.tree['height'] = 5 if 5 < len(data) else len(data)
        section_treetable.pack(fill='x')

        save_button = ttk.Button(self, text="Apply Comment on all processes", command=self.apply_all_process)
        save_button.pack()

        self.word_text = scrolledtext.ScrolledText(self, undo=True)
        self.word_text.insert("1.0", pe_comments['pid'][int(self.pid)][str(self.path)][0])
        self.word_text.bind('<KeyPress>', self.save_comment)
        self.word_text.pack(side=tk.BOTTOM, fill='both', padx=10, pady=2)

class PEImports(Frame):

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        label = tk.Label(self, text="Imports", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)
        headers = ("Dll Name", "Hint", "Func Address", "Function Name")
        data = self.controller.imports
        imp_treetable = TreeTable(self, headers=headers, data=data)
        imp_treetable.tree['height'] = 22 if 22 < len(data) else len(data)
        imp_treetable.pack(expand=YES, fill=BOTH)

class PEExports(Frame):

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        label = tk.Label(self, text="Exports", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)
        headers = ("Hint", "Func Address", "Func Name")
        data = self.controller.exports
        exp_treetable = TreeTable(self, headers=headers, data=data)
        exp_treetable.tree['height'] = 22 if 22 < len(data) else len(data)
        exp_treetable.pack(expand=YES, fill=BOTH)

class MemStrings(Frame):

    def insert_text(self):
        '''
        This function insert the text to the memory strings textbox.
        :return: None
        '''
        self.text.configure(state='normal')
        good_unicode = self.display_text
        self.text.insert('1.0', good_unicode)
        self.text.configure(state='disabled')
        self.text.pack(expand=YES, fill=BOTH)

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        label = tk.Label(self, text="Memory Strings", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)

        self.display_text = self.controller.mem_strings #"Strings"

        xscrollbar = Scrollbar(self, orient=HORIZONTAL)
        xscrollbar.pack(side=BOTTOM, fill=X)

        # Vertical (y) Scroll Bar
        yscrollbar = Scrollbar(self)
        yscrollbar.pack(side=RIGHT, fill=Y)

        # Text Widget
        self.text = Text(self, wrap=NONE, state='disabled',
                    xscrollcommand=xscrollbar.set,
                    yscrollcommand=yscrollbar.set)
        self.insert_text()

        # Configure the scrollbars
        xscrollbar.config(command=self.text.xview)
        yscrollbar.config(command=self.text.yview)

class ImageStrings(Frame):

    def insert_text(self):
        '''
        This function insert the image strings to the textbox
        :return:
        '''
        self.text.configure(state='normal')
        good_unicode = self.display_text
        self.text.insert('1.0', good_unicode)
        self.text.configure(state='disabled')
        self.text.pack(expand=YES, fill=BOTH)

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        label = tk.Label(self, text="Image Strings", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)

        self.display_text = self.controller.image_strings #"Strings"

        xscrollbar = Scrollbar(self, orient=HORIZONTAL)
        xscrollbar.pack(side=BOTTOM, fill=X)

        # Vertical (y) Scroll Bar
        yscrollbar = Scrollbar(self)
        yscrollbar.pack(side=RIGHT, fill=Y)

        # Text Widget
        self.text = Text(self, wrap=NONE, state='disabled',
                    xscrollcommand=xscrollbar.set,
                    yscrollcommand=yscrollbar.set)
        self.insert_text()

        # Configure the scrollbars
        xscrollbar.config(command=self.text.xview)
        yscrollbar.config(command=self.text.yview)

#endregion DllProperties

class memInfo(tk.Tk):

    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        lb_info = tk.Label(self, text="Paging Lists(K)\nZeroed: {}\nFree: {}\nModified: {}\nModifiedNoWrite: {}\nPageFileModified: {}\nStandby: {}".format(pfn_stuff['MmZeroedPageListHead'] or "", pfn_stuff['MmFreePageListHead'] or "", pfn_stuff['MmModifiedPageListHead'] or "", pfn_stuff['MmModifiedNoWritePageListHead'] or "", '' or "", pfn_stuff['MmStandbyPageListHead'] or ""))
        lb_info.pack()

        pfn_total_numbers = {0:0,
                             1:0,
                             2:0,
                             3:0,
                             4:0,
                             5:0,
                             6:0,
                             7:0,}
        for pid in pfn_stuff:

            try:
                pid = int(pid)
                for priority in pfn_stuff[pid]:
                    pfn_total_numbers[priority] += pfn_stuff[pid][priority]

            # part of the list head counters
            except:
                continue

        priority_info = tk.Label(self,
                           text="Priority 0: {}\nPriority 1: {}\nPriority 2: {}\nPriority 3: {}\nPriority 4: {}\nPriority 5: {}\nPriority 6: {}\nPriority 7: {}".format(
                             pfn_total_numbers[0], pfn_total_numbers[1], pfn_total_numbers[2], pfn_total_numbers[3], pfn_total_numbers[4], pfn_total_numbers[5], pfn_total_numbers[6], pfn_total_numbers[7]))
        priority_info.pack()

#region HexDump

class HexDump(tk.Toplevel):

    def __init__(self,file_name, file_data, row_len, *args, **kwargs):
        tk.Toplevel.__init__(self, *args, **kwargs)
        self.title_font = tkFont.Font(family='Helvetica', size=16, weight="bold", slant="italic")

        self.row_len = row_len
        self.file_name = file_name
        self.file_data = file_data
        self.file_mem = file_data

        self.var = tk.StringVar()

        if not type(self.file_mem) is dict:
            self.file_mem = {0:self.file_mem}

        for mem_type in self.file_mem:
            self.file_data = self.file_mem[mem_type]
            strings_data = self.file_mem[mem_type].decode('ascii', errors='ignore').encode().replace('       ', '')
            self.good_data = get_ascii_unicode(self.file_data)[0]

            if len(self.good_data) > 5:
                self.file_data = self.file_mem[mem_type]
                break

        tabcontroller = NoteBook(self)
        self.frames = {}

        # Create all the classes (tabs in the properties).
        for F in (HDHexDump, HDStrings):
            page_name = F.__name__
            frame = F(parent=tabcontroller, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky=E + W + N + S)
            tabcontroller.add(frame, text=page_name)

        tabcontroller.enable_traversal()
        tabcontroller.pack(fill=BOTH, expand=1)

class HDStrings(Frame):

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        label = tk.Label(self, text="Strings", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)
        self.strings_tree = TreeTable(self, headers=("Offset", "Strings"), data=self.controller.good_data, resize=True)#True)
        self.strings_tree.tree['height'] = 22 if 22 < len(self.controller.good_data) else len(self.controller.good_data)
        self.strings_tree.pack(expand=YES, fill=BOTH)

class HDHexDump(Frame):

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        label = tk.Label(self, text="HexDump", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)
        data = []
        strings_data = self.controller.file_data.decode('ascii', errors='replace')
        hex_data = self.controller.file_data
        sio_len = len(hex_data)
        sio_hex = StringIO .StringIO(hex_data)
        sio_string = StringIO.StringIO(strings_data)
        data=[]
        counter = 0

        # Slice the file data in chunks of self.row_len.
        for i in range(sio_len/self.controller.row_len):
            counter += self.controller.row_len
            hexank = ''
            for i in sio_hex.read(self.controller.row_len):
                c_value = str(hex(ord(i)))[2:]
                if len(c_value) == 1:
                    c_value = '0{}'.format(c_value)
                hexank += ' {}'.format(c_value)
            data.append((str(hex(counter)), hexank , sio_string.read(self.controller.row_len)))
        data.append((str(hex(counter+self.controller.row_len)), sio_hex.read(), sio_string.read(self.controller.row_len)))

        self.values_table = TreeTable(self, headers=("Offset", "Hex", "Data"), data=data, resize=True)
        self.values_table.tree['height'] = 22
        self.values_table.pack(expand=YES, fill=BOTH)

#endregion HexDump

class RegViewer(Frame):
    '''
    Gui class to display the registry
    This class will update the table every time the user expand a item in the treeview, so if there is a new item to display
    (VolExp/RegistryGui search in the backgruond for more keys) he will insert directly to the tree.
    '''
    def __init__(self, master, dict, headers, reg_api, *args, **kwargs):
        Frame.__init__(self, master, *args, **kwargs)
        self.back_button = ttk.Button(self, text="\t Registry")
        self.back_button.pack(fill='x')
        self.panedWindow = ttk.Panedwindow(self, orient=tk.HORIZONTAL)  # orient panes horizontally next to each other
        self.panedWindow.pack(fill=tk.BOTH, expand=True)                # occupy full master window and enable expand property

        self.frame1 = ttk.Frame(self.panedWindow, width=200, height=300, relief=tk.SUNKEN)
        self.frame2 = ttk.Frame(self.panedWindow, width=400, height=400, relief=tk.SUNKEN)

        self.panedWindow.add(self.frame1, weight=1)
        self.panedWindow.add(self.frame2, weight=3)
        self.values_table = None
        self.last_id_clicked = None

        # Init the radio button for value, data search.
        self.var = tk.StringVar()
        self.r1 = ttk.Radiobutton(self.frame2, text='View Data (Slow, Searching).', width=20, variable=self.var, value=True,
                             command=self.viewKeys,
                             style='IndicatorOff.TRadiobutton')
        self.r1.pack(fill='x')
        self.r2 = ttk.Radiobutton(self.frame2, text="Don\'t View Data (Fast).", width=20, variable=self.var, value=False,
                             command=self.viewKeys,
                             style='IndicatorOff.TRadiobutton')
        self.r2.pack(fill='x')

        known_users = ["LocalService", "NetworkService", "LocalSystem"]
        self.headers = headers
        self.dict = dict
        data = []
        hives_list = self.dict.keys()

        # Remove a flag from the hive_list (this flag indicate if we done get all the keys).
        if 'Finish build hives' in hives_list:
            hives_list.remove('Finish build hives')

        # Go all over the hive list and insert them to the table.
        for key in hives_list:
            my_tup = None

            if key != "|properties|":

                my_tup = tuple([0 for i in range(len(self.headers)-1)])

                if self.dict[key].has_key("|properties|"):
                    my_tup = self.dict[key]["|properties|"]
                my_tup = (key,) + my_tup if type(my_tup) == tuple else (key,str(my_tup))
                my_tup = (my_tup[1], my_tup[0]) # reverse order??
                data.append(my_tup)

        self.current_directory = "<- \t \\"
        self.directory_queue = []

        self.headers = headers

        # Create the treeview table  and the scroll bar(this is the only table in this project that don't use TreeTable).
        sb = Scrollbar(self.frame1)
        sb.pack(side=RIGHT, fill='y')
        self.keys = Treeview(self.frame1, yscrollcommand=sb.set)
        sb.config(command=self.keys.yview)
        self.keys['columns'] = ('one')
        self.keys.column('one')
        self.keys.heading("#0", text="Key Name")
        self.keys.heading("one", text="Last Write Time")

        # Insert the data to the table
        for key in data:
            folder = self.keys.insert('', END, values=(key[0],), text=key[1])

        # Go and search deeper for each data.
        for folder in self.keys.get_children():
            self.__init_items__(folder)

        # Init events
        self.keys.bind("<Double-1>", self.OnDoubleClick)
        self.keys.bind("<Return>", self.OnDoubleClick)
        self.keys.bind("<space>", self.OpenWithoutSearch)
        self.keys.bind('<<TreeviewOpen>>', self.OpenWithoutSearch)
        #self.keys.bind('<Control-k>', self.control_k)
        self.keys.bind('<Right>', self.OnDoubleClick)
        self.keys.pack(expand=YES, fill=BOTH)
        self.regapi = reg_api#registryapi.RegistryApi(volself._config)
        self.tree = self.keys
        self.row_search = ('', 0)
        self.tree.bind('<KeyPress>', self.allKeyboardEvent)

    def get_all_children(self, item="", only_opened=True):
        '''
        This function get all children and sub children
        :param item: the parent id
        :param only_opened: flag to get only the keys that opend
        :return: list of all the children id of the tree.
        '''
        open_opt = tk.BooleanVar()
        children = []

        # Go all over the item under this item
        for child in self.tree.get_children(item):
            children.append(child)

            # Check if this item is open, and if so go recursivly inside.
            open_opt.set(str(self.tree.item(child, option='open')))
            if open_opt.get() or not only_opened:
                children += self.get_all_children(child, only_opened)
        return children

    def allKeyboardEvent(self, event):
        '''
        This function go to the item key that start with the key pressed by the user
        like file explorer feature.
        '''

        # Check if this is proper keyboard event
        if event.keysym_num > 0 and event.keysym_num < 60000:

            # Get the current item selected or the first item from the tree.
            if len(self.tree.selection()) > 0 :
                item = self.tree.selection()[0]
            else:
                item = self.tree.get_children('')[0]
            clicked_item = item

            # Check the time between each key pressed (after 2 seconds its stop)
            if time.time() - self.row_search[1] > 2:
                self.row_search = ('', self.row_search[1])

            # Check for the same character twice in a row.
            if len(self.row_search[0]) == 1 and self.row_search[0][0] == event.char.lower():
                self.row_search = (self.row_search[0][0], time.time())
            else:
                self.row_search = ('{}{}'.format(self.row_search[0], event.char.lower()), self.row_search[1])
            after_selected = False

            childrens = self.get_all_children()

            # Check all the rows after the current selection.
            for ht_row in childrens:
                if clicked_item == ht_row:#self.tree.item(ht_row, "text").lower():
                    after_selected = True
                    if time.time() - self.row_search[1] > 2 or len(self.row_search[0]) == 1:
                        continue
                if not after_selected:
                    continue
                if self.tree.item(ht_row, "text").lower().startswith(self.row_search[0]):
                    self.tree.focus(ht_row)
                    self.tree.selection_set(ht_row)
                    self.tree.see(ht_row)
                    self.row_search = (self.row_search[0], time.time())
                    return


            # Check all the rows before the current selection.
            for ht_row in childrens:
                if clicked_item == ht_row:#self.tree.item(ht_row, "text").lower():
                    break

                if self.tree.item(ht_row, "text").lower().startswith(self.row_search[0]):
                    self.tree.focus(ht_row)
                    self.tree.selection_set(ht_row)
                    self.tree.see(ht_row)
                    self.row_search = (self.row_search[0], time.time())
                    return

            print '\a'
            self.row_search = ('', 0)

    def __init_items__(self, folder, count=0, maxim=2):
        '''
        This function go inside the dict and insert always two(default->maxim) subfolder inside each item (if there is any).
        :param folder: opend folder
        :param count: current count (for the recursive use don't change it)
        :param maxim: the depth of this recursive to get subkeys.
        :return: None
        '''
        if count == maxim:
            return
        count+=1

        children = self.keys.get_children(folder)
        if children:
            for c_item in children:
                self.keys.delete(c_item)

        clicked_file = self.keys.item(folder,"text")
        full_path = ""
        parent_iid = 1
        item_iid = folder

        # Get the parent id
        while parent_iid:
            item_name = self.keys.item(item_iid, 'text')
            parent_iid = self.keys.parent(item_iid)
            full_path = "{}\{}".format(item_name, full_path)
            item_iid = parent_iid

        # Get the full path.
        if full_path.find('\\') == -1:
            full_path += "\\{}".format(clicked_file)
        if full_path[-1] == '\\':
            full_path = full_path[:-1]

        # Get the current key.
        path_list = full_path.split("\\")
        pMftExp = self.dict
        counter = 0
        for key in path_list:
            counter+=1
            if pMftExp.has_key(key):
                pMftExp = pMftExp[key]


        # Get the data to the table.
        data = []
        for key in pMftExp.keys():
            if key != "|properties|":
                my_tup = tuple([0 for i in range(len(self.headers)-1)])
                if pMftExp[key].has_key("|properties|"):
                    my_tup = pMftExp[key]["|properties|"]
                my_tup = (key,) + my_tup if type(my_tup) == tuple else (key,str(my_tup))
                my_tup = (my_tup[1], my_tup[0]) # reverse order??
                data.append(my_tup)

        # Insert the key to the table
        for key in data:
            self.keys.insert(folder, END, values=key, text=key[1])

        # Go inside for each key
        for child in self.keys.get_children(folder):
            self.__init_items__(child, count)

    def disabe_enable_reg_viewer(self, disable=True):
        '''
        This disable/enable the buttons and tree widgets
        :param disable: default to disable (change to False to enable)
        :return: None
        '''
        change_widget_state([self.r1, self.r2], 'disable' if disable else 'enable')

        # Disable/Enable the treeview
        if disable:

            # "Delete" all the binding
            self.tree.bind('<Button-1>', lambda e: 'break')
            self.keys.bind('<<TreeviewOpen>>', lambda e: 'break')
            self.keys.bind('<<TreeviewClose>>', lambda e: 'break')
            self.keys.bind('<Left>', lambda e: 'break')
            self.keys.bind('<Right>', lambda e: 'break')
            self.keys.bind('<Up>', lambda e: 'break')
            self.keys.bind('<Down>', lambda e: 'break')
        else:

            # "Restore" all the binding to the normal state.
            self.tree.unbind('<Button-1>')
            self.keys.unbind('<<TreeviewClose>>')
            self.keys.unbind('<Left>')
            self.keys.unbind('<Right>')
            self.keys.unbind('<Up>')
            self.keys.unbind('<Down>')
            self.keys.bind('<<TreeviewOpen>>', self.OpenWithoutSearch)
        self.keys.state((('disabled' if disable else '!disabled'), ))
        #print self.keys.state()
        time.sleep(1)

    def viewKeys(self):
        '''
        This function show the init stuff to show the vales table.
        :return: None
        '''
        # Exit if the user click the same button or key.
        if self.var.get() == '' or ((int(self.var.get()) and str(self.values_table) != 'None') or (int(self.var.get() ==0) and str(self.values_table) == 'None')):
            return

        # If we want to search the keys.
        if int(self.var.get()):
            self.show_tables()
        elif str(self.values_table) != 'None':
            self.values_table.destroy()
            self.values_table = None

    def show_tables(self):
        '''
        Create the load table and start the function to search the keys.
        :return: None
        '''
        # Destroyd the previews table.
        if str(self.values_table) != str(None):
            self.values_table.destroy()
            self.values_table = None

        # Return if no item selected.
        if len(self.keys.selection()) == 0:
            return

        # Disable treeview and buttons
        self.disabe_enable_reg_viewer()

        # Create the load table
        item = self.keys.selection()[0]

        # Check if this key is already display
        if self.last_id_clicked == item and str(self.values_table) != 'None':
            return

        self.last_id_clicked = item
        full_path = ""
        parent_iid = 1
        item_iid = item

        # Get the parent id
        while parent_iid:
            item_name = self.keys.item(item_iid, 'text')
            parent_iid = self.keys.parent(item_iid)
            full_path = "{}\{}".format(item_name, full_path)
            item_iid = parent_iid

        threading.Thread(target=self.show_table_thread, args=(full_path, )).start()
        data = [('Searching, please wait', ), ('The data will appear when it\'s done.', )]
        self.values_table = TreeTable(self.frame2, headers=("Status",), data=data, resize=True)
        self.values_table.tree['height'] = 22
        self.values_table.pack(expand=YES, fill=BOTH)

    def show_table_thread(self, full_path):
        '''
        This function search for the key and send the result to the queue to build it in the treetable of data|type|value.
        :param item: the selected item id
        :return: None
        '''

        print "[+] Get key {}".format(full_path)

        # Get the hive name.
        hive_name = full_path.split('\\')[0]
        data = []
        full_path = full_path[len(hive_name)+1:-1]
        self.regapi.reset_current()

        # Go all over the data in this key and get the values.
        for key, _ in self.regapi.reg_yield_key(hive_name, key = full_path):

            # Get the values.
            for v in rawreg.values(key):
                tp, dat = rawreg.value_data(v)
                value, typ, data_info, addr = v.Name, tp, dat, v

                # If this is default key(the value name is None).
                if value == None:

                    # if data_info is null then is not set and we add it later
                    if not data_info:
                        data_info = '(value not set)'


                    data.append(('(Default)', typ, data_info, addr))

                # Check if the type sould represent in hexa.
                elif typ in ('REG_BINARY', 'REG_FULL_RESOURCE_DESCRIPTOR', 'REG_RESOURCE_LIST'):
                    data.append((str(value), typ, data_info.encode('hex'), addr.v()))
                elif type(data_info) is list:
                    data.append((str(value), typ, data_info, addr.v()))
                else:
                    data.append((str(value), typ, data_info, addr.v()))

        # Check if default value is not set(set it to 0).
        flag = True
        for i in data:
            if '(Default)' in i:
                flag = False

        # Put the default key (if we didn't find any).
        if flag:
            data = [('(Default)', 'Unknown', '(value not set)', "")] + data

        def create_table(self, data):

            # If the gui exit in the process or before
            try:
                self.values_table.destroy()
                self.values_table = TreeTable(self.frame2, headers=("Value Name", "Type", "Data", "Address"), data=data, resize=True)
                self.values_table.tree.bind("<Double-1>", self.view_value_data)
                self.values_table.tree.bind("<Return>", self.view_value_data)
                self.values_table.tree['height'] = 22
                self.values_table.pack(expand=YES, fill=BOTH)
                self.disabe_enable_reg_viewer(False)
            except tk.TclError:
                pass

        queue.put((create_table, (self, data)))

    def view_value_data(self, event=None):
        '''
        This function show the data for the key pressed.
        '''
        item = self.values_table.tree.selection()[0]
        key_name = self.values_table.tree.item(item,"text")
        value, typ, data_info, addr = self.values_table.tree.item(item)["values"]

        # If this is not represent in hexa.
        if not typ in ('REG_BINARY', 'REG_FULL_RESOURCE_DESCRIPTOR', 'REG_RESOURCE_LIST'):
            messagebox.showinfo("Value info ({})".format(key_name), "Value name: {}\nValue type: {}\nValue Data: {}\n(This type of key cannot be represented in binary format\n[You can also get this info from the table])".format(value, typ, data_info), parent=self)

        # If the data represent in hexa.
        else:
            file_data = {0:str(data_info).decode('hex')}
            app = HexDump(file_name=key_name, file_data=file_data, row_len=16)
            app.title('Value info ({})'.format(key_name))
            window_width = 1050/2
            window_height = 600
            width = app.winfo_screenwidth()/2
            height = app.winfo_screenheight()
            app.geometry('%dx%d+%d+%d' % (window_width, window_height, width*0.5-(window_width/2), height*0.5-(window_height/2)))
            app.mainloop()

    def OpenWithoutSearch(self, event):
        '''
        This Function run self.OnDoubleClick with flag that make it not run search every time we open some item but still search this item
        :param event: event
        :return: None
        '''
        self.OnDoubleClick('DontRun')

    def OnDoubleClick(self, event):
        '''
        Go deep inside the items.
        :param event: event
        :return: None
        '''
        item = self.keys.selection()[0]
        self.__init_items__(item, 0)
        clicked_file = self.keys.item(item,"text")
        full_path = ""
        parent_iid = 1
        item_iid = self.keys.selection()[0]

        # Get the parent id
        while parent_iid:

            item_name = self.keys.item(item_iid, 'text')
            parent_iid = self.keys.parent(item_iid)
            full_path = "{}\{}".format(item_name, full_path)
            item_iid = parent_iid
        item = self.keys.selection()[0]

        # Get the path
        if full_path.find('\\') == -1:
            full_path += "\\{}".format(clicked_file)
        if full_path[-1] == '\\':
            full_path = full_path[:-1]

        self.directory_queue.append(self.current_directory)
        self.current_directory = full_path
        self.back_button["text"] = self.current_directory

        # Check if the user want do display the table (Slow mode).
        if self.var.get() != '' and int(self.var.get()) and (not (self.last_id_clicked == item and str(self.values_table) != 'None')) and (event != 'DontRun'):#if str(self.values_table) != 'None' and (event.keycode == 32 or event.keycode == 13): # apply also only enter or space
            self.show_tables()

class Explorer(Frame):
    '''
    Gui class to display explorer like (from dictionary inside dictionary inside dictionary...)
    Each key will be the first item in the table, padding with the tuple that inside the '|properties|' item
    if there is no '|properties|' key in some key the information will be 0 padding
    Thats also mean that you cannot create in your table on the first column a item named "|properties|"
    '''
    def __init__(self, master, my_dict, headers, searchTitle, resize=True, path=None, relate=None, *args, **kwargs):
        Frame.__init__(self, master, *args, **kwargs)

        # Configure gird
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Init var
        self.relate = relate
        self.headers = headers
        self.searchTitle = searchTitle
        self.dict = my_dict

        # Create the top frame (for the buttons and the entry).
        top_frame = ttk.Frame(self)

        # Config search button
        self.button_go_back = ttk.Button(top_frame, text="<-", command=self.GoBack, width=5)
        ToolTip(self.button_go_back, 'Forward (Alt + Left Arrow)')
        self.button_go_back.pack(side=tk.LEFT)
        self.button_ungo_back = ttk.Button(top_frame, text="->", command=self.UnGo, width=5)
        ToolTip(self.button_ungo_back, 'Forward (Alt + Right Arrow)')
        self.button_ungo_back.pack(side=tk.LEFT)
        self.search_button = tk.Button(top_frame, image=volself.search_exp_image_icon, command=self.control_f, height = 20, width = 20)
        self.search_button.pack(side=tk.RIGHT)
        ToolTip(self.search_button, 'Search')

        # Config directory entry
        self.entry_directory = ttk.Entry(top_frame)
        self.entry_directory.bind("<KeyRelease>", self.KeyRelease)
        self.entry_directory.bind("<FocusOut>", lambda e: self.after(250, self.FoucusOut))
        self.entry_directory.bind("<Return>", self.LVEnter)
        self.entry_directory.pack(fill='x', ipady=1, pady=1)
        self.c_selection = 0

        top_frame.pack(side=tk.TOP, fill='x')

        # Get all the data
        data, directories = self.GetDataAndDirectories(self.dict)

        # Init stuff like button, tree and bind events
        self.current_directory = ""
        self.last_data = self.last_tw = self.tw = None
        self.directory_queue = []
        self.directory_requeue = []
        self.tree = TreeTable(self, headers=headers, data=data, resize=resize)
        self.tree.tree['height'] = 22 if 22 < len(data) else len(data)
        self.tree.pack(expand=YES, fill=BOTH)
        self.tree.tree.bind("<Alt-Left>", self.GoBack)
        self.tree.tree.bind("<BackSpace>", self.GoBack)
        self.tree.tree.bind("<Alt-Right>", self.UnGo)
        self.tree.tree.bind("<Double-1>", self.OnDoubleClick)
        self.tree.tree.bind("<Return>", self.OnDoubleClick)
        self.tree.tree.bind('<Control-f>', self.control_f)
        self.tree.tree.bind('<Control-F>', self.control_f)
        if has_csv:
            self.tree.HeaderMenu.delete(5)
            self.tree.HeaderMenu.insert_command(5, label='Export Explorer To Csv', command=self.export_table_csv)

        # Tag the directories with "tag_directory" so all will be colored with yellow
        self.tree.tree.tag_configure('tag_directory', background=_from_rgb((252, 255, 124)))
        self.tree.visual_drag.tag_configure('tag_directory', background=_from_rgb((252, 255, 124)))

        # Tag all the directories (inside the directories list) with the "tag_directory".
        for i in self.tree.tree.get_children():
            dir_name = self.tree.tree.item(i,"text")

            # Insert the directory to colored tag
            if dir_name in directories:
                self.tree.tree.item(i, tags="tag_directory")
                self.tree.visual_drag.item(i, tags="tag_directory")

        # Go to the path specify if specify
        if path:
            self.GoToFile(path, True)
        else:

            # If the first explorer have only one item go inside this item (recursively).
            change_path = ''
            while len(my_dict) == 1:
                self.directory_queue.append(change_path)
                change_path = '{}\\{}'.format(change_path, my_dict.keys()[0])
                my_dict = my_dict[my_dict.keys()[0]]

            # Go to the directory.
            self.GoTo(change_path)

        # Bind exit if this is toplevel.
        if not relate or self.winfo_toplevel() != relate:
            def on_exit():
                self.DetroyLV()
                self.master.destroy()

            # Exit the popup list.
            self.winfo_toplevel().protocol("WM_DELETE_WINDOW", on_exit)

    def control_f(self, event=None):
        '''
        This function spawn the search window.
        :param event: None
        :return: None
        '''
        app = ExpSearch(controller=self, dict=self.dict, dict_headers=self.headers)
        x = self.relate.winfo_x() + 333
        y = self.relate.winfo_y()
        app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
        app.title(self.searchTitle)
        app.geometry("500x300")

    def export_table_csv(self):
        ''' Export the table to csv file '''
        ans = messagebox.askyesnocancel("Export to csv",
                                        "Did you mean to export all the explorer data or just this specific table?\npress yes to all the data", parent=self)
        if ans == None:
            return

        selected = tkFileDialog.asksaveasfilename(parent=self)
        if selected and selected != '':

            def export_specific_dict(csv_writer, dict, path):

                # Go all over the dictionary.
                for key in dict:

                    # Return if this is the information key.
                    if key == '|properties|':
                        continue

                    # If we want to export all the data or just the current
                    if ans:
                        csv_writer.writerow(['{} {}'.format('~' * path.count('\\'), key)] + (list(dict[key]['|properties|']) if dict[key].has_key('|properties|') else [0 for i in range(len(self.headers)-1)]))
                    elif path == self.current_directory:
                        csv_writer.writerow(['{} {}'.format('~' * path.count('\\'), key)] + (list(dict[key]['|properties|']) if dict[key].has_key('|properties|') else [0 for i in range(len(self.headers)-1)]))
                        continue
                    elif not path.lower() in self.current_directory.lower():
                        return

                    export_specific_dict(csv_writer, dict[key], '{}\{}'.format(path, key))


            with open(selected, 'w') as fhandle:
                csv_writer = csv.writer(fhandle)
                csv_writer.writerow(self.headers)
                export_specific_dict(csv_writer, self.dict, '')

    def GetDBPointer(self, path, not_case_sensitive=False, return_none_on_bad_path=False):
        '''
        Return the specific dictionary (inside the db dict [self.dict]) that describe the given path
        :param path: the path to describe
        :param not_case_sensitive: False - > case sensitive
        :return: db pointer dictionary somewhere inside the dictionary that describe the given path.
        '''
        db_pointer = self.dict
        path_list = path.split("\\")

        # Remove none item.
        if path_list[0] == '':
            path_list = path_list[1:]

        # Return in empty path.
        if return_none_on_bad_path and len(path_list) == 0:
            return

        current_path = ''
        index = 0
        for key in path_list:
            if db_pointer.has_key(key):
                db_pointer = db_pointer[key]

            # Search with lower case
            elif not_case_sensitive:
                for c_key in db_pointer:
                    if c_key.lower() == key.lower():
                        db_pointer = db_pointer[c_key]
                        break
                else:

                    if len(path_list) == index+1:
                        continue

                    if return_none_on_bad_path:
                        return

                    # Unable to find the full go_to path
                    ans = messagebox.askyesnocancel("Notice",
                                                    "Unnable to find this path ({}),\n\nThis path found: {}\nDo you want to go there?".format(
                                                        path, current_path), parent=self)
                    if not ans:
                        return
                    else:
                        # Set the curernt directory.
                        self.current_directory = current_path
                        self.entry_directory.delete(0, tk.END)
                        self.entry_directory.insert(0, self.current_directory)
                        return db_pointer

            elif return_none_on_bad_path and len(path_list) -1  > index:
                return
            index += 1
            current_path += '\{}'.format(key)

        # Set the curernt directory.
        self.current_directory = path
        self.entry_directory.delete(0, tk.END)
        self.entry_directory.insert(0, self.current_directory)
        return db_pointer

    def GetDataAndDirectories(self, db_pointer):
        '''
        Return the data, directory for a given pointer in the dictionary db
        data - > the data sould be displayed for the db_pointer directory
        directories - > is the directories that inside the data
        :param db_pointer: pointer in the directory db (self.my_dict)
        :return: (data, directories)
        '''
        data = []
        directories = []
        for key in db_pointer.keys():

            # Get all the data from the "|properties|" key in each dictionary key that have properties (informatio)
            if key != "|properties|":

                # Get the row items from the "|properties|" key.
                # Pad with zero in case there is no "|properties|" key.
                if db_pointer[key].has_key("|properties|"):
                    my_tup = db_pointer[key]["|properties|"]
                else:
                    my_tup = tuple([0 for i in range(len(self.headers) - 1)])

                # If this is directory insert it to the directories list witch will be colored in yellow.
                if len(db_pointer[key]) - db_pointer[key].has_key("|properties|") > 0:
                    directories.append(key)

                # Append the key name to the tuple.
                my_tup = (key,) + my_tup if type(my_tup) == tuple else (key, str(my_tup))

                # Insert the spesific row to the list of all the rows.
                data.append(my_tup)
        return data, directories

    def KeyRelease(self, event=None):
        '''
        Display all the directories inside the current directory
        :param event: None
        :return: None
        '''
        data = self.entry_directory.get()

        # If key down or up or left or right or enter return and let the other handle handle it.
        if event and event.keysym_num in [65361, 65362, 65363, 65293]:
            return
        elif event and event.keysym_num in [65364, 65307] and self.tw and self.tw.winfo_exists(): # Key down

            # If ESC pressed detroyd the window and return
            if event.keysym_num == 65307:
                self.DetroyLV()

            return

        # Return if non printable key pressed (nothing add to the entry_directory).
        elif event and event.keysym_num != 65364:# and self.tw:
            if data == self.last_data:
                return

        if self.tw:
            self.DetroyLV()

        # Add the \ if the entry is empty.
        if data == '':
            data = '\\'

        self.last_data = data

        db_pointer = self.GetDBPointer(data, True, return_none_on_bad_path=True)

        # Alert the user that this path not exist (except if he try to delete).
        if not db_pointer:
            if not (event and event.keysym.lower() == 'backspace'):
                self.bell()
                messagebox.showerror('Error', 'Explorer Can\'t Find {},\nCheck the spelling and try again.'.format(data), parent=self)
            return

        values = []

        # Get all the good directories based on the user type.
        for dir in self.GetDataAndDirectories(db_pointer)[1]:
            c_path = '{}\\{}'.format(data[:data.rfind('\\')], dir)

            # Good data
            if data.lower() in c_path.lower():
                values.append(c_path)

        # If there is more than one dir than post.
        if len(values) > 0:

            # Get position to post the toplevel.
            x = self.entry_directory.winfo_rootx()
            y = self.entry_directory.winfo_rooty() + 20

            # Create the top level with frame.
            self.last_tw = str(self.tw)
            self.tw = tw = tk.Toplevel()
            self.my_frame = ttk.Frame(self.tw, width=self.entry_directory.winfo_reqwidth() - 1)
            self.values = values
            tw.wm_overrideredirect(1)
            tw.wm_geometry("+%d+%d" % (x, y))

            # Create and pack the listbox with scrollbar
            self.lv = lv = tk.Listbox(self.my_frame, height = len(values) if len(values) < 10 else 10)
            self.scrollbar = scrollbar = Scrollbar(self.my_frame, orient="vertical")
            scrollbar.config(command=self.lv.yview)
            scrollbar.pack(side=tk.RIGHT, fill="y")
            self.lv.config(yscrollcommand=scrollbar.set)
            lv['selectmode'] = tk.SINGLE

            # Bind commands.
            self.entry_directory.bind("<Return>", self.LVEnter)
            self.entry_directory.bind('<Up>', self.Up)
            self.entry_directory.bind('<Down>', self.Down)

            # Insert data to the list (all the pathes).
            for dis in values:
                lv.insert(END, dis)

            # Select the first item.
            lv.selection_set(0)

            # Bind Escape - > destroy and click -> open to the listbox.
            lv.bind("<Escape>", self.DetroyLV)
            #lv.bind('<Button-1>', self.LVEnter)
            lv.bind('<ButtonRelease-1>', self.LVEnter)

            # pack all the data.
            lv.pack(fill=tk.BOTH)
            self.my_frame.pack(fill=tk.BOTH)
            self.update()

            # Windows destroyed..
            try:
                h = self.lv.winfo_geometry().split('x')[1].split('+')[0]
                tw.geometry("{}x{}".format(self.entry_directory.winfo_width() - 2, h))
            except tk.TclError:
                pass

    def Down(self, event):
        '''
        KeyDown event - set selection to one down item
        :param event: None
        :return: None
        '''

        # Cleare the selected item
        self.lv.selection_clear(self.c_selection)

        # Add one if we less or equals to the number of elements in the list else 0
        self.c_selection = self.c_selection + 1 if self.c_selection < len(self.values) - 1 else 0

        # Go to view the item and select.
        self.lv.yview(self.c_selection)
        self.lv.selection_set(self.c_selection)

    def Up(self, event):
        '''
        KeyUp event - set selection to one up item
        :param event: None
        :return: None
        '''
        # If we on the top destroyed.
        if self.c_selection == 0:
            self.DetroyLV()
            return

        # Set selection and position to the selected item.
        self.lv.selection_clear(self.c_selection)
        self.c_selection -= 1
        self.lv.yview(self.c_selection)
        self.lv.selection_set(self.c_selection)

    def LVEnter(self, event=None):
        '''
        On enter/ click go to the selected item set the directory entry and detroyed the listbox.
        :param event: None
        :return: None
        '''

        # Check if we exit the window and this didnt destroyd
        if not self.entry_directory.winfo_exists():
            self.tw.destroy()
            return

        # If there is no goto and popup return.
        if self.tw and len(self.lv.curselection()) != 0:
            go_to = self.lv.get(self.lv.curselection())
        else:
            go_to = self.entry_directory.get()

        # Go to the self.entry_directory.
        self.GoTo(go_to, True)

        # Update the entry directory (add \ to the end and generate keyrelease).
        if not self.current_directory.endswith('\\'):
            self.entry_directory.delete(0, tk.END)
            self.entry_directory.insert(0, '{}\\'.format(self.current_directory))

        self.KeyRelease(None) #self.entry_directory.event_generate('<KeyRelease>')

        self.entry_directory.focus_set()

    def FoucusOut(self, event=None):
        '''
        If we not focus some element of the toplevel exit.
        :param event: None
        :return: None
        '''

        # Check if we focus out the entry and the top level or some of his elements.
        if self.tw and not self.focus_get() in [self.last_tw, self.tw, self.my_frame, self.lv, self.scrollbar] and not self.entry_directory.focus_get().__class__ == ttk.Entry:
            self.DetroyLV()

    def DetroyLV(self, event=None):
        '''
        Destroyd the listbox and unbind all the current unnecessary binding methonds.
        :param event:
        :return:
        '''

        # Do this only if the top exist.
        if self.tw and self.tw:
            self.tw.destroy()
            self.tw = None
            #del self.tw
            self.c_selection = 0
            #self.entry_directory.bind('<Return>', lambda e: 'break')
            self.entry_directory.bind("<Return>", self.LVEnter)
            self.entry_directory.bind('<Up>', lambda e: 'break')
            self.entry_directory.bind('<Down>', lambda e: 'break')

    def OnDoubleClick(self, event):
        '''
        This function open directory (replace all the items in the tree to the subdirectory that was double clicked).
        :param event: None
        :return: None
        '''

        # Reset the user search
        self.tree.row_search = ('', 0)

        # Double click on table header to resize
        if event and event.y < 25 and event.y > 0:
            try:
                if self.tree.tree.identify_region(event.x, event.y) == 'separator':
                    self.tree.resize_col(self.tree.tree.identify_column(event.x))
                return
            except tk.TclError:
                return

        # Double click where no item selected
        elif len(self.tree.tree.selection()) == 0 :
            return

        # Get the selected item
        item = self.tree.tree.selection()[0]
        clicked_file = self.tree.tree.item(item, "text")
        tags = self.tree.tree.item(item, "tags")
        if not 'tag_directory' in tags:
            return

        # Append the current directory to the last visited directory list (self.directory_queue).
        self.directory_queue.append(self.current_directory)

        # Change the current directory
        if self.current_directory.endswith('\\'):
            self.current_directory += clicked_file
        else:
            self.current_directory += "\{}".format(clicked_file)

        # Get the selected item from the database dictionary.
        path = self.current_directory
        db_pointer = self.GetDBPointer(path)

        # Get all the data
        data, directories = self.GetDataAndDirectories(db_pointer)

        # Validate that this is directory (more that 0 files inside)
        if len(data) > 0:

            # Reset the undo list
            self.directory_requeue = []

            # Delete the previews data
            for i in self.tree.tree.get_children():
                self.tree.tree.delete(i)
                self.tree.visual_drag.delete(i)

            # Insert the new data.
            self.tree.insert_items(data)

            # Append the all the directories from the directories_list to the tag_directory (so they will colored as directory).
            for i in self.tree.tree.get_children():
                dir_name = self.tree.tree.item(i,"text")
                if dir_name in directories:
                    self.tree.tree.item(i, tags="tag_directory")
                    self.tree.visual_drag.item(i, tags="tag_directory")

    def UnGo(self, event=None):
        '''
        This function is undo fore goback.
        :param event: None
        :return: None
        '''

        # Reset the user search
        self.tree.row_search = ('', 0)

        # Check that the directory_queue is not empty (the list of the directories history).
        if len(self.directory_requeue) > 0:

            # Go to the last directory.
            prev_dir = self.directory_requeue.pop()
            self.GoTo(prev_dir, True)

    def GoBack(self, event=None):
        '''
        This function go to the previews directory.
        :param event: None
        :return: None
        '''

        # Reset the user search
        self.tree.row_search = ('', 0)

        # Check that the directory_queue is not empty (the list of the directories history).
        if len(self.directory_queue) > 0:

            # Go to the last directory.
            last_dir = self.directory_queue.pop()
            self.GoTo(last_dir, True, False)

    def GoTo(self, go_to, not_case_sensitive=False, go_back=True):
        '''
        This function go to a spesific specified path
        :param goto: path to go (string)
        :param not_case_sensitive: if to check not as case sensetive.
        :param go_back: are we go back or forward.
        :return: None
        '''

        # Add to the right queue (go back or forward).
        if go_back:
            self.directory_queue.append(self.current_directory)
        else:
            self.directory_requeue.append(self.current_directory)

        # Get the selected item from the database dictionary.
        db_pointer = self.GetDBPointer(go_to, not_case_sensitive)

        # If the user dont want to go to the location (because the location doesn't exist in the dump).
        if not db_pointer:
            return

        # Delete current displayed data from the treeview.
        for i in self.tree.tree.get_children():
            self.tree.tree.delete(i)
            self.tree.visual_drag.delete(i)

        # Get all the data
        data, directories = self.GetDataAndDirectories(db_pointer)

        # Insert the data and tag the directories as directory.
        self.tree.insert_items(data)
        for i in self.tree.tree.get_children():
            dir_name = self.tree.tree.item(i, "text")
            if dir_name in directories:
                self.tree.tree.item(i, tags="tag_directory")
                self.tree.visual_drag.item(i, tags="tag_directory")

    def GoToFile(self, file_path, not_case_sensitive):
        '''
        Go to the directory and select the file.
        :param file_path: the file path
        :param not_case_sensitive: not case sensitive
        :return: None
        '''

        # Go to the directory.
        go_to = file_path[:file_path.rfind('\\')+1]
        self.GoTo(go_to, not_case_sensitive)

        # Go all over the items and select the right one.
        file_name = file_path[file_path.rfind('\\')+1:]
        for ht_row in self.tree.tree.get_children():
            if str(self.tree.tree.item(ht_row)['values'][0]).lower() == str(file_name).lower():
                self.tree.tree.focus(ht_row)
                self.tree.tree.selection_set(ht_row)
                queue.put((self.tree.tree.see, (ht_row,)))

class FileExplorer(Frame):
    '''
    Explorer with file specific function like dump file.
    '''
    def __init__(self, master, dict, headers, searchTitle, resize=True, path=None, relate=None,  *args, **kwargs):
        Frame.__init__(self, master, *args, **kwargs)

        self.pw = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        self.exp_frame = Explorer(self.pw, dict[' '], headers, searchTitle, resize, path, relate, *args, **kwargs)
        self.tree = self.exp_frame.tree
        self.exp_frame.tree.aMenu.add_command(label='HexDump', command=self.HexDump)
        self.exp_frame.tree.aMenu.add_command(label='Dump', command=self.Dump)


        #info_frame = ttk.Frame(self.pw)
        tabcontroller = NoteBook(self.pw)

        # Check if there is any data in the dict.
        if dict['?userassist?'] != []:
            ua_frame = Frame(tabcontroller)
            headers = ('Registry', 'Path', 'Last Write', 'Subkey', 'Value (file path)', 'ID', 'Count', 'Focus Count', 'Time Focused', 'Last Updated')
            display_headers = ('Value (file path)', 'ID', 'Count', 'Focus Count', 'Last Write')
            ua_frame.tree = TreeTree(ua_frame, headers=headers, data=dict['?userassist?'], text_by_item=4, resize=False, display=display_headers)
            ua_frame.tree.aMenu.add_command(label='Jump To Location', command=lambda: self.resolve_path_and_go_to(ua_frame.tree.main_t))
            ua_frame.tree.pack(expand=YES, fill=BOTH)
            tabcontroller.add(ua_frame, text='User Assist')

        # Check if there is any data in the dict.
        if dict['?shimcache?'] != []:
            sc_frame = Frame(tabcontroller)
            headers = ('Last Modified', 'Last Update', 'Path (file path)')
            display_headers = ('Path (file path)', 'Last Modified')
            sc_frame.tree = TreeTree(sc_frame, headers=headers, data=dict['?shimcache?'], text_by_item=2, resize=False, display=display_headers)
            sc_frame.tree.aMenu.add_command(label='Jump To Location', command=lambda: self.resolve_path_and_go_to(sc_frame.tree.main_t))
            sc_frame.tree.pack(expand=YES, fill=BOTH)
            tabcontroller.add(sc_frame, text='Shim Cache')

        # Check if there is any data in the dict.
        if dict['?amcache?'] != []:
            amc_frame = Frame(tabcontroller)
            headers = ('Registry', 'Key Path', 'Last Write', 'Value Name', 'Description', 'Value (file path)')
            display_headers = ('Value (file path)', 'Last Write')
            amc_frame.tree = TreeTree(amc_frame, headers=headers, data=dict['?amcache?'], text_by_item=6, resize=False, display=display_headers)
            amc_frame.tree.aMenu.add_command(label='Jump To Location', command=lambda: self.resolve_path_and_go_to(amc_frame.tree.main_t))
            amc_frame.tree.pack(expand=YES, fill=BOTH)
            tabcontroller.add(amc_frame, text='Am Cache')

        # Check if there is any shimcachemem in the dict.
        if dict['?shimcachemem?'] != []:
            scm_frame = Frame(tabcontroller)
            headers = ('Order', 'Last Modified', 'Last Update', 'Exec Flag', 'File Size', 'File Path')
            display_headers = ('File Path', 'Last Modified')
            scm_frame.tree = TreeTree(scm_frame, headers=headers, data=dict['?shimcachemem?'], text_by_item=5, resize=False, display=display_headers)
            scm_frame.tree.aMenu.add_command(label='Jump To Location', command=lambda: self.resolve_path_and_go_to(scm_frame.tree.main_t))
            scm_frame.tree.pack(expand=YES, fill=BOTH)
            tabcontroller.add(scm_frame, text='Shim Cache Mem')

        tabcontroller.enable_traversal()
        tabcontroller.pack(fill=BOTH, expand=1)


        self.pw.add(tabcontroller)
        self.pw.add(self.exp_frame)
        self.pw.pack(fill=BOTH, expand=YES)

    def resolve_path_and_go_to(self, tree):
        '''
        Resolve environment, symlink and go to the file specified.
        :param path:
        :return:
        '''

        item = tree.tree.selection()[0]
        path = tree.tree.item(item)['values'][tree.text_by_item].replace('UEME_RUNPIDL:', '').replace('UEME_RUNPATH:', '').lower()

        # "System" Envars (checked from csrss, wininit and exporer, on this order).
        for c_pid in process_bases:
            if process_bases[int(c_pid)]["dlls"].has_key('csrss.exe'):
                if process_env_var.has_key(int(c_pid)):
                    for env in process_env_var[int(c_pid)]:
                        path = path.replace('%{}%'.format(env.lower()), process_env_var[int(c_pid)][env])

        for c_pid in process_bases:
            if process_bases[int(c_pid)]["dlls"].has_key('wininit.exe'):
                if process_env_var.has_key(int(c_pid)):
                    for env in process_env_var[int(c_pid)]:
                        path = path.replace('%{}%'.format(env.lower()), process_env_var[int(c_pid)][env])

        for c_pid in process_bases:
            if 'explorer.exe' in [c_exp.lower() for c_exp in process_bases[int(c_pid)]["dlls"].keys()]:
                if process_env_var.has_key(int(c_pid)):
                    for env in process_env_var[int(c_pid)]:
                        path = path.replace('%{}%'.format(env.lower()), process_env_var[int(c_pid)][env])

        if path.startswith('\\') or path.startswith('/'):
            path = path[1:]
        path = path.replace('/', '\\')
        if '\\' in path:
            path = path.replace('\\\\', '\\')
            if path.startswith('??'):
                path = path[3:]
            path_split = path.split('\\')
        else:
            # Remove the /??/ on the starts of some path
            if path.startswith('/??/'):
                path = path[4:]
            path_split = path.split('/')

        drive = path_split[0].upper()

        # Validate drive
        if winobj_dict == {}:
            messagebox.showerror('Error', 'Need winobj data to resolve this path,\nPlease try again later when you have winobj data.\nOr go to this path.'.format(drive), parent=self)
            return
        elif not winobj_dict['/']['GLOBAL??'].has_key(drive):
            messagebox.showerror('Error', 'Invalid Drive: {}'.format(drive), parent=self)
            return
        device = winobj_dict['/']['GLOBAL??'][drive]['|properties|'][-2].replace('Target: ', '')
        path_split = [device] + path_split[1:]
        change_path = "\\".join(path_split)

        self.exp_frame.GoToFile(change_path, True)

    def dump_directory(self, clicked_file, recursive=True):
        '''
        Try to dump a direcroty
        :param clicked_file: dir name
        :param values: dir values
        :return: None
        '''
        current_directory = "{}\{}".format(self.exp_frame.current_directory, clicked_file)
        path_list = current_directory.split("\\")
        pMftExp = self.exp_frame.dict
        for key in path_list:
            if pMftExp.has_key(key):
                pMftExp = pMftExp[key]

        current_path = os.path.join(volself._config.DUMP_DIR, key)

        # Check if this directory already exists
        if os.path.isdir(current_path):
            ans = messagebox.askyesnocancel("Notice", "This folder ({}) is already exists, Do you want to continue?".format(os.path.abspath(current_path)), parent=self)

            # If the directory exists check if the user dont want to continue
            if not ans:
                return
        else:
            os.makedirs(current_path)

        threading.Thread(target=self.dump_dir_summon, args=(pMftExp, current_path, recursive)).start()

    def dump_dir_summon(self, pMftExp, current_path, recursive):
        '''
        This function summun the dump directory function and alert the user when the directory dumped.
        :param pMftExp: pointer to the current key in the database to dump.
        :param current_path: the dump directory on the local host.
        :param recursive: to dump recursively.
        :return: None
        '''
        # Summon the function as a thread.
        t = threading.Thread(target=self.dump_dir, args=(pMftExp, current_path, recursive))
        t.start()

        # Wait for the thread to finish, popup and display the result
        t.join()
        print "[+] Dump Directory", "File Directory - Dump File Done ({}).".format(current_path)
        queue.put((messagebox.showinfo, ("Dump Directory", "File Directory - Dump File Done ({}).".format(current_path), ('**kwargs', {'parent': self}))))

    def dump_dir(self, pMftExp, current_path, recursive=True):
        '''
        This function dump a directory
        :param pMftExp: pointer to the current key in the database to dump.
        :param current_path: the dump directory on the local host.
        :param recursive: to dump recursively.
        :return: None
        '''
        for key in pMftExp.keys():
            c_path = os.path.join(current_path, key)

            # If this is directory create it
            if type(pMftExp[key]) is dict and len(pMftExp[key]) - pMftExp[key].has_key("|properties|") > 0:

                # Create the directory.
                if not os.path.exists(c_path):
                    os.makedirs(c_path)

                # Go and dump this directory as well (recursive).
                if recursive:
                    self.dump_dir(pMftExp[key], c_path)
            else:

                # Continue if this is the parent key properties and not a real file.
                if key == "|properties|":
                    continue

                # Try to dump the file
                try:
                    values = pMftExp[key]["|properties|"]
                    clicked_addr = values[-1]

                    # Fix conflict that looks like files inside file
                    if len(os.path.split(current_path)) > 1 and not os.path.exists(current_path):
                        os.makedirs(current_path)

                    # Create the additional plugin dir (to get all the extraction types from memory [very verbose]).
                    if not os.path.exists(os.path.join(current_path, 'Files With Type (Plugin Creation)')):
                        os.makedirs(os.path.join(current_path, 'Files With Type (Plugin Creation)'))

                    data = dump_explorer_file(clicked_addr, os.path.join(current_path, 'Files With Type (Plugin Creation)')).values()

                    # Get the biggest data from all the extraction types that we get from the memory.
                    good = ''
                    for c_data in data:
                        if len(c_data) > len(good):
                            good = c_data

                    # Create the file.
                    with open(os.path.join(current_path, key), 'wb') as my_file:
                        my_file.write(good)

                    print "[+] File Explorer - Dump File Done ({}).".format(key)
                except Exception:
                    print "[-] File Explorer - Dump File Failed ({}).".format(key)
    def Dump(self):
        '''
        This function check if the selected item is directory or a file and call the suitable function.
        :return: None
        '''

        # Get the arguments for the function
        item = self.exp_frame.tree.tree.selection()[0]
        clicked_file = self.exp_frame.tree.tree.item(item, "text")

        # Check if this is directory or a file.
        if 'tag_directory' in self.exp_frame.tree.tree.item(item, "tags"):
            self.dump_directory(clicked_file, True)
        else:
            values = self.exp_frame.tree.tree.item(item)["values"]
            threading.Thread(target=self.DumpThread, args=(values,)).start()
            time.sleep(1)

    def DumpThread(self, values):
        '''
        This function dump explorer file in a thread.
        :param clicked_file: the file name
        :param values: the values of the spesific table item
        :return: None
        '''

        # Try to dump the file.
        try:
            clicked_addr = values[-1]
            dump_explorer_file(clicked_addr)
            queue.put((messagebox.showinfo, ("Dump File", "File Explorer - Dump File Done ({}).".format(values[0]), ('**kwargs', {'parent': self}))))
        except Exception:
            queue.put((messagebox.showerror, ("Dump File", "File Explorer - Dump File Failed ({}).".format(values[0]), ('**kwargs', {'parent': self}))))

    def HexDump(self):
        '''
        This function validate that the selected item is a file and call the hexdump function.
        :return:
        '''
        item = self.exp_frame.tree.tree.selection()[0]

        # Validate that the selected item is a file and not directory, if this is directory, return.
        if 'tag_directory' in self.exp_frame.tree.tree.item(item, "tags"):
            messagebox.showerror("Error", "Unable to dump a Directory", parent=self)
            return

        # Start the HexDumpThread function.
        clicked_file = self.exp_frame.tree.tree.item(item, "text")
        values = self.exp_frame.tree.tree.item(item)["values"]
        threading.Thread(target=self.HexDumpThread, args=(clicked_file, values)).start()
        time.sleep(1)

    def HexDumpThread(self, clicked_file, values):
        '''
        This function dump explorer file in a thread.
        :param clicked_file: the file name
        :param values: the values of the specific table item
        :return: None
        '''
        clicked_addr = values[-1]
        try:
            file_mem = dump_explorer_file(clicked_addr)

            def create_hex_dump(clicked_file, file_mem):
                # Spawn the hexdump window.
                app = HexDump(clicked_file, file_mem, 16)
                app.title(clicked_file)
                window_width = 1050
                window_height = 800
                width = app.winfo_screenwidth()
                height = app.winfo_screenheight()
                app.geometry('%dx%d+%d+%d' % (
                window_width, window_height, width * 0.5 - (window_width / 2), height * 0.5 - (window_height / 2)))

            queue.put((create_hex_dump, (clicked_file, file_mem)))

        except Exception as ex:
            print 'exception:',ex
            def show_message_func():
                messagebox.showerror("Error", "Unable to dump this file (Make sure it is a file and not a Directory)", parent=self)

            queue.put((show_message_func, ()))

class WinObjExplorer(Explorer):
    """
    Explorer like gui for structs.
    """

    NAME_TO_TYPE = {# 'ALPC Port:': '',
                    # 'Callback': '_CALLBACK_OBJECT', # keep check
                    'Device': '_DEVICE_OBJECT',
                    #'Directory': '',
                    'Driver': '_DRIVER_OBJECT',
                    'Event': '_KEVENT',     # ---------------------------------
                    'Job': '_EJOB',         # todo-> check them on all version
                    'Mutant': '_KMUTANT',   # ---------------------------------
                    'Section': '_SECTION_OBJECT', # This object replace in windows 10.
                    'Semaphore': '_KSEMAPHORE',
                    #'Session': '',
                    'SymbolicLink': '_OBJECT_SYMBOLIC_LINK',
                    'WindowStation': 'tagWINDOWSTATION',
                    'Type': '_OBJECT_TYPE',}

    def __init__(self, master, dict,  headers=("Object Name", "Type", "Info", "Addr"), searchTitle='Search For Kernel Objects', resize=False, path=None, relate=None, *args, **kwargs):
        Explorer.__init__(self, master, dict, headers, searchTitle, resize, path, relate, *args, **kwargs)

        self.tree.aMenu.add_command(label='Struct Analyze', command=self.run_struct_analyze)
        self.tree.aMenu.add_command(label='Object Info', command=self.get_obj_info)

    def OnDoubleClick(self, event):
        '''
        This function hook on double click for symbolic link and go to the symbolic link.
        :param event: event
        :return: None
        '''
        # Reset the user search
        self.tree.row_search = ('', 0)

        # Double click on table header to resize
        if event and event.y < 25 and event.y > 0:
            try:
                if self.tree.tree.identify_region(event.x, event.y) == 'separator':
                    self.tree.resize_col(self.tree.tree.identify_column(event.x))
                return
            except tk.TclError:
                return

        # Double click where no item selected
        elif len(self.tree.tree.selection()) == 0:
            return

        item = self.tree.tree.selection()[0]
        if self.tree.tree.item(item)['values'][1] == 'SymbolicLink':
            self.GoToFile(self.tree.tree.item(item)['values'][2].replace('Target: ', '\/'), False)
        elif self.tree.tree.item(item)['values'][1] == 'Device':
            self.GoToFile(self.tree.tree.item(item)['values'][2].replace('Driver: ', '\/'), False)
        else:
            Explorer.OnDoubleClick(self, event)

    def run_struct_analyze(self):
        '''
        get address and send to the struct analyze function.
        '''
        item = self.tree.tree.selection()[0]
        type = self.tree.tree.item(item)['values'][1]
        if not WinObjExplorer.NAME_TO_TYPE.has_key(type):
            print '[-] WinObjExplorer dont support struct analyze on this object ({})'.format(type)
            return
        struct_type = WinObjExplorer.NAME_TO_TYPE[type]

        addr = self.tree.tree.item(item)['values'][-1]
        if not addr:
            print "[-] Unable to find the address of this {}".format(struct_type)
            return
        print "[+] Run Struct Analyze on {}, addr: {}".format(struct_type, addr)
        threading.Thread(target=run_struct_analyze, args=(struct_type, addr)).start()

    def get_obj_info(self):
        type_to_type_name = {'Key': 'Registry', }
        not_supported_yet = ['File', 'Registry']

        item = self.tree.tree.selection()[0]
        data = self.tree.tree.item(item)['values']
        obj_type = data[1]

        # Validate name
        if obj_type in type_to_type_name:
            obj_type = type_to_type_name[obj_type]

        # Validate that we know how to parse this type of object (from handle table)
        if obj_type in not_supported_yet:
            messagebox.showerror("Error!", "Sorry,\nThis object parsing is not supported from here.",
                                 parent=self)
            return

        obj_va = data[-1]
        obj_name = data[0]

        obj_info_conf = conf.ConfObject()
        obj_info_conf.readonly = {}
        obj_info_conf.PROFILE = volself._config.PROFILE
        obj_info_conf.LOCATION = volself._config.LOCATION
        obj_info_conf.KDBG = volself._config.KDBG
        obj_info_kaddr_space = utils.load_as(obj_info_conf)

        oh = obj.Object("_OBJECT_HEADER", obj_va - obj_info_kaddr_space.profile.get_obj_offset('_OBJECT_HEADER', 'Body'), obj_info_kaddr_space)

        # Get The Data
        try:
            data = get_security_info(oh, obj_info_kaddr_space, obj_type)
        except TypeError:
            messagebox.showerror("Error!", "Sorry,\nUnable to parse the SID object", parent=self)
            return

        # Create the top level
        app = tk.Toplevel()
        x = root.winfo_x()
        y = root.winfo_y()
        app.geometry("+%d+%d" % (x + ABS_X + 200, y + ABS_Y + 30))
        ObjectProperties(app, data).pack(fill=BOTH, expand=YES)
        app.title("{} - {} :{} Properties".format(obj_type, obj_name, obj_va))
        window_width = 550
        window_height = 600
        app.geometry('%dx%d' % (window_width, window_height))

class ExpSearch(tk.Toplevel):
    '''
    Search for explorer class, handle explorer ctrl+f
    '''
    def __init__(self, headers=('Path', 'Name', 'Value'), dict=None, dict_headers=None, controller=None, *args, **kwargs):#(path,name,value)
        tk.Toplevel.__init__(self, *args, **kwargs)

        # Init variables
        self.headers = headers
        self.dict = dict
        self.dict_headers = dict_headers
        self.controller = controller

        # Init and pack the class gui.
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.search_text = tk.Entry(self)
        self.search_text.insert(10, 'Search text here')
        self.search_text.bind("<Return>", self.search)
        self.search_text.pack()
        self.select_box = Combobox(self, state="readonly", values=self.dict_headers)
        self.select_box.current(0)
        self.select_box.pack()
        self.search_button = tk.Button(self, text="<- Search ->", command=self.search)
        self.search_button.pack(fill='x')
        self.tree = TreeTable(self, headers=headers, data=[], text_by_item=1, resize=True)
        self.tree.pack(expand=YES, fill=BOTH)

        # Bind and focus
        self.tree.tree.bind("<Return>", self.OnDoubleClick)
        self.tree.tree.bind("<Double-1>", self.OnDoubleClick)
        self.search_text.bind("<FocusIn>", self.focus_in)
        self.search_text.focus()

    def focus_in(self, event=None):
        '''
        This function mark all the text inside the text widget for convenience.
        :param event: None
        :return: None
        '''
        self.search_text.selection_range(0, tk.END)

    def OnDoubleClick(self, event):
        '''
        This fucntio go to the selected item in the parent explorer.
        :param event: None
        :return: None
        '''
        # Double click on table header to resize
        if event and event.y < 25 and event.y > 0:
            try:
                if self.tree.tree.identify_region(event.x, event.y) == 'separator':
                    self.tree.resize_col(self.tree.tree.identify_column(event.x))
                return
            except tk.TclError:
                return
        # Double click where no item selected
        elif len(self.tree.tree.selection()) == 0 :
            return

        # Go and select the clicked item.
        item = self.tree.tree.selection()[0]
        clicked_file_path = self.tree.tree.item(item)['values'][0]
        file_name = self.tree.tree.item(item)['values'][1]
        self.controller.GoToFile('{}\{}'.format(clicked_file_path, file_name), False)

    def recurse_search(self, current_path, current_dir_files):
        '''
        A recursive function that go deep inside the dictionary database and look inside the '|properties|' key to find the searched item
        :param current_path: key name (item name in the explorer)
        :param current_dir_files: a pointer to the current dictionary to search inside
        :return: None, its insert the data to the self.found_data (witch later be insert to the table) or call itself recursive inside.
        '''

        # The item the user want to search
        my_index = self.dict_headers.index(self.select_box.get())-1

        # Go all over the database dictionary.
        for c_file in current_dir_files:

            # If it's not the item properties (this is another database).
            if c_file != '|properties|':

                # If the user search for the first box (the item name) than we append the data here.
                if self.dict_headers.index(self.select_box.get()) == 0:

                    # if this data match the user search than insert it
                    if self.text_to_search in c_file.lower():
                        self.found_data.append((current_path, c_file))
                self.recurse_search('{}\\{}'.format(current_path, c_file),current_dir_files[c_file])

            # If this is the item properties.
            else:

                # If this is what the user search for than insert the item to the table.
                if self.text_to_search in str(tuple(current_dir_files[c_file])[my_index]).lower():
                    self.found_data.append((current_path[:current_path.rfind('\\')], current_path[current_path.rfind('\\')+1:], str(tuple(current_dir_files[c_file])[my_index])))

    def search(self, event=None):
        '''
        The search handle function that summon the self.recursive_search function.
        :return: None, this function will insert all the founded item to the table.
        '''

        self.text_to_search = self.search_text.get().lower()
        print "[+] searching for: {}".format(self.text_to_search), 'in', self.select_box.get(),'index:', self.dict_headers.index(self.select_box.get())-1

        # Remove previouse searched items.
        for i in self.tree.tree.get_children():
            self.tree.tree.delete(i)
            self.tree.visual_drag.delete(i)

        self.found_data = []

        # Search for files.
        for c_file in self.dict:

            # Go all over the files.
            if c_file != '|properties|':
                self.recurse_search(c_file, self.dict[c_file])

        # Insert all the data to the table
        self.tree.insert_items(self.found_data)

class StructExplorer(Explorer):
    """
    Explorer like gui for structs.
    """
    def __init__(self, master, dict, sa_self,  headers=("Struct Name", "Member Value", "Struct Address", "Object Type"), searchTitle='Search', writeSupport=False, relate=None, *args, **kwargs):
        Explorer.__init__(self, master, dict, headers, searchTitle, relate, *args, **kwargs)

        # Init Class Variables.
        self.sa_self = sa_self
        self.relate = master
        self.pid = int(sa_self.PID) if hasattr(sa_self, 'PID') and sa_self.PID else 4
        self.app = None

        # Add write support feature if enable.
        if writeSupport:
            self.tree.aMenu.add_command(label="Write", command=self.RunWrite)
        self.tree.aMenu.add_command(label='Dereference As:', command=self.dereference)

    def RunWrite(self, wt=1):
        """
        Write to the dump file the new data.
        :param wt: the index of the column in the table
        :return: None
        """
        row = self.tree.tree.selection()[0]
        item = self.tree.tree.item(row)
        item_text = item['values'][wt]
        new_val = tkSimpleDialog.askstring(title="Change {}".format(item['values'][0]), prompt="Notice\nThere is no back option after you change this value\n(the data type will adjust to the current field)\nCurrent: {}\nNew:".format(item_text), parent=self)

        # The user cancel.
        if not new_val:
            return

        # Write to the struct in memory:
        s = item['values'][0]  # [my_item['values'][0].index('.') + 1:]
        struct_addr = item['values'][2]
        struct_type = item['values'][3]

        ex = 'change addresses is not supported'
        # Check if hex number.
        if new_val.startswith('0x'):
            try:
                new_val = int(new_val, 16)
            except (TypeError, ValueError):
                pass
        elif new_val.isdigit():
            new_val = int(new_val)

        result = False
        try:
            struct = obj.Object(struct_type, struct_addr, self.sa_self.kaddr_space)
            result = struct.write(new_val)
        except Exception as ex:
            print '[-] unable to parse this object (addr: {}, type: {})'.format(struct_addr, struct_type)
            print ex
        if result:
            # Change the item in the table:
            good_vals = list(item['values'])
            good_vals[wt] = new_val
            self.tree.tree.item(row, values=good_vals)
            print '[+] Write Operation Success'
        else:
            print '[-] Write Operation Failed {}'.format(ex)

    def dereference(self):
        '''
        Handle to Dereference As function, calls to self.dereference_func and open the SmartChoose gui.
        :return: None
        '''
        # Get all the profile vtypes and sort it.
        my_list = list(self.sa_self.kaddr_space.profile.vtypes.keys())
        my_list = sorted(my_list, key=str.lower)
        default_struct = '_EPROCESS'

        # Open the SmartChoose to let the user pick an struct.
        app = SmartChoose(my_list, self.dereference_func, default=my_list[my_list.index(default_struct)])

        # Place the object near to the relate.
        if self.relate:
            x = self.relate.winfo_x()
            y = self.relate.winfo_y()
            app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
        app.geometry("500x50")
        app.title('Please choose your real struct type')
        app.resizable(False, False)

    def dereference_func(self, app):
        '''
        This function dereference to the selected struct.
        :param app: the SmartChoose app
        :return: None
        '''
        item = self.tree.tree.selection()[0]
        my_item = self.tree.tree.item(item)
        struct_addr = my_item['values'][1]
        struct_type = my_item['values'][3]

        # Error if the user try to dereference an function.
        if struct_type == 'Function':
            messagebox.showerror("Error", "This is a Volatility function, not a member of the struct (you can't change this).", parent=self)
            return

        # Dereference the struct.
        struct = obj.Object(struct_type, struct_addr, self.sa_self.kaddr_space)

        # Check if this struct specified address is in the physical layer (usually came from scan plugin that scan the physical layer)
        if not struct or not struct.is_valid():
            struct = obj.Object(struct_type, struct_addr, self.sa_self.kaddr_space.physical_space(), native_vm=self.sa_self.kaddr_space)
            if not struct or not struct.is_valid():
                struct = obj.Object(struct_type, struct_addr, self.sa_self.kaddr_space)

        # Check if the struct is valid
        if struct:
            struct = struct.dereference_as(app.dereference)

        # Check if the struct is valid after the dereference and if not alert the user and ask if he want to continue (the struct type is realy matter only on the table the previews derefrence doesn't realy matter).
        if not struct or not struct.is_valid():

            # Return if the user dont want to continue
            if not messagebox.askyesnocancel('Notice', 'Volatility didn\'t recognize {} struct in this address\nare you sure you want to continue?\n(Dereferenced as valid struct: {} (struct.is_valid())(or this struct is none))'.format(app.dereference, 'False'), parent=app):
                return

        # Change the type in the explorer.
        good_values = list(my_item['values'])
        good_values[1] = struct.v() if (good_values[-1] != app.dereference) and hasattr('struct', 'v') else good_values[1] # obj.Object(app.dereference, good_values[1], self.sa_self.kaddr_space).v()
        good_values[-1] = app.dereference
        self.tree.tree.item(item, values=good_values)
        app.destroy()

    def OnDoubleClick(self, event):
        '''
        This function handle double click on any kind of item in the table (wheter is an function or not).
        :param event: None
        :return: None
        '''
        global queue
        # Double click on table header to resize
        if event and event.y < 25 and event.y > 0:
            try:
                if self.tree.tree.identify_region(event.x, event.y) == 'separator':
                    self.tree.resize_col(self.tree.tree.identify_column(event.x))
                return
            except tk.TclError:
                return
        # Double click where no item selected
        elif len(self.tree.tree.selection()) == 0:
            return

        item = self.tree.tree.selection()[0]
        clicked_file = self.tree.tree.item(item, "text")
        my_item = self.tree.tree.item(item)

        # Get chiled structs:
        s = my_item['values'][0]
        struct_addr = my_item['values'][2]
        struct_type = my_item['values'][3]

        # Set the current_directory.
        if struct_type !='Function':
            self.directory_queue.append(self.current_directory)
            self.current_directory += "\{}".format(clicked_file)
            self.entry_directory.delete(0, tk.END)
            self.entry_directory.insert(0, self.current_directory)

        path_list = self.current_directory.split("\\")
        struct_path = ''
        pMftExp = self.dict

        # Go inside the database.
        for key in path_list:
            if pMftExp.has_key(key):
                pMftExp = pMftExp[key]
                struct_path += '.{}'.format(key)

        # Run volatility function
        if struct_type == 'Function':

            # Get the base object (of this struct analyzer).
            title = self.master.title()
            p_type = title[len('Struct Analyzer  '): title.rfind('(') - 1]
            addr = title[title.rfind('(') + 1: title.rfind(')')]
            struct = obj.Object(p_type, addr, self.sa_self.kaddr_space)

            # Check if this struct specified address is in the physical layer (usually came from scan plugin that scan the physical layer)
            if not struct or not struct.is_valid():
                struct = obj.Object(p_type, addr, self.sa_self.kaddr_space.physical_space(), native_vm=self.sa_self.kaddr_space)
                if not struct or not struct.is_valid():
                    struct = obj.Object(p_type, addr, self.sa_self.kaddr_space)

            # Walk from the base struct to the current struct.
            if len(struct_path) > 0:
                struct = get_right_member(struct, [struct_path[1:]])

            function = getattr(struct, s)

            # Check if the function invalid
            if isinstance(function, obj.NoneObject):
                messagebox.showerror("Error", "This struct is None object ({}).".format(repr(function)), parent=self)
                return

            # Check if function take arguments
            _args = get_func_args(function)
            arguments = _args.args
            default_arguments = _args.defaults

            # Check if this function get an argument.
            if arguments:
                exit_if = False

                # Remove the self argument from the prompt if this function is part of a class.
                if 'self' in arguments:

                    # If the function have only one arguments disable the createion of the prompt
                    if len(arguments) == 1:
                        exit_if = True
                        arguments = []
                    else:
                        arguments = list(arguments)
                        arguments.remove('self')
                        arguments = tuple(arguments)

                # Display the arguments prompt if the function get any arguments.
                if not exit_if:
                    arguments_data = {}

                    for _key in arguments:
                        arguments_data[_key] = ''

                    # Add the default arguments
                    if default_arguments:
                        default_arguments_dict = {}
                        default_arguments_len = len(default_arguments)
                        arguments_len = len(arguments)

                        # Create the argument dict
                        for _key in range(default_arguments_len):
                            default_arguments_dict[arguments[arguments_len - (1 + _key)]] = default_arguments[default_arguments_len - (1 + _key)]

                        # Create the argument data dict for the popup class window(value is string)
                        for _key in default_arguments_dict:
                            _val = default_arguments_dict[_key]
                            arguments_data[_key] = str(_val)

                    self.dict_options = arguments_data
                    def set_options(dict_options):

                        # Check to convert user data to python types else just keep it string (as input).
                        for opt in dict_options:
                            if dict_options[opt] == '':
                                dict_options[opt] = 'None'
                            try:
                                dict_options[opt] = eval(dict_options[opt])
                            except NameError:
                                pass
                        self.dict_options = dict_options

                    # Return if there is already an argument popup on the screen.
                    if self.app != None:
                        return

                    # Create the popup.
                    self.app = PopUp(arguments_data, set_options)
                    if self.relate:
                        x = self.relate.winfo_x()
                        y = self.relate.winfo_y()
                        self.app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
                    self.app.grab_release()
                    self.app.title('{} Arguments:'.format(s))
                    self.app.geometry("450x{}".format(str(int(len(arguments_data)+1)*40)))
                    self.app.attributes('-topmost', 1)
                    self.app.done = False

                    def on_exit():
                        # Handle Exit Event
                        self.app.done = 'Exit'
                        self.app.destroy()
                    self.app.protocol("WM_DELETE_WINDOW", on_exit)

                    # Wait util the user finish
                    while not self.app.done:
                        time.sleep(0.2)
                        root.update_idletasks()
                        root.update()

                    # Return if the user exit the window
                    if self.app.done == 'Exit':
                        self.app = None
                        return

                    # Destroy the app and init the self.app to None(the user finish after the while)
                    self.app.destroy()
                    self.app = None

                    # Order the arguments.
                    good_arguments = []
                    for c_arg in arguments:
                        good_arguments.append(self.dict_options[c_arg])
                    arguments = good_arguments

            def run_function_in_thread(self, function, arguments, s):
                '''
                This funcion get an volatility function to run with the arguments, run the function and return a popup to the user.
                This function run as a thead to make sure the gui not freeze.
                :param function: The function to run
                :param arguments: The function parameters
                :return: None
                '''
                global queue

                # The function may fail.
                try:

                    # Run the function with arguments
                    if arguments and len(arguments) > 0:

                        # Run the function with one arguments
                        if len(arguments) == 1:
                            struct = function(arguments[0])

                        # Run the function with more than one arguments.
                        else:
                            struct = function(*arguments)

                    # Run the function without any arguments
                    else:
                        struct = function()
                except Exception as ex:
                    queue.put((messagebox.showerror, ("Error", "This function failed at run time.", ('**kwargs', {'parent': self}))))
                    return

                # Check if the return value is generator
                if inspect.isgenerator(struct):
                    try:
                        return_gen_list = list(struct)
                    except Exception as err:
                        queue.put((messagebox.showerror, ("Error", "This function failed at run time (probably one of your parameters is incorrect).\n\nErorr:\n{}".format(err), ('**kwargs', {'parent': self}))))
                        return
                    if len(return_gen_list) == 0:
                        queue.put((messagebox.showerror, ("Error", "This function returned none.", ('**kwargs', {'parent': self}))))
                        return

                    # Fix the list to be list of tuples if its not.
                    if not type(return_gen_list[0]) in (tuple,list):
                        return_gen_list = [(x,) for x in return_gen_list]

                    # Search for object inside the values returend (and display them)
                    find_object = False
                    for i in return_gen_list[0]:

                        # Check if there is a Struct object inside that generator.
                        if isinstance(i, obj.CType):
                            print '[+] find struct inside the result:', type(i)
                            find_object = True
                            _data = []
                            for j in return_gen_list:
                                _struct = j[return_gen_list[0].index(i)]
                                _data.append((_struct.obj_type, _struct.obj_offset))

                            def create_object_generator(_data, i, s):
                                '''
                                Create a list(generetor) and display it in a table, create an Double-Click event that summon struct analyzer.
                                :param _data: the data
                                :param i: the struct
                                :param s: struct name
                                :return: None
                                '''
                                def run_new_sa(event):
                                    '''
                                    This function run a struct analyzer inside the generator (if the generator return objects)
                                    :param event:
                                    :return:
                                    '''
                                    _self = event.widget
                                    _item = _self.selection()[0]
                                    _my_item = _self.item(_item)
                                    run_struct_analyze(_my_item['values'][0], _my_item['values'][1], pid=int(_self.pid))

                                # Init the top level
                                _app = tk.Toplevel()
                                _x = self.relate.winfo_x()
                                _y = self.relate.winfo_y()
                                _app.geometry("+%d+%d" % (_x + ABS_X, _y + ABS_Y))
                                _headers = [str(x) for x in range(len(_data[0]))]
                                _treetable = TreeTable(_app, headers=_headers, data=_data)
                                p_struct = i

                                # Recursive search of the parent object.
                                while p_struct.obj_parent != None:
                                    p_struct = p_struct.obj_parent

                                # Check if that object have UniqueProcessId and if so make sure we using the right virtual memory.
                                if hasattr(p_struct, 'UniqueProcessId'):
                                    _treetable.tree.pid = int(p_struct.UniqueProcessId)
                                else:
                                    _treetable.tree.pid = 4

                                # Pack the data.
                                _treetable.run_new_sa = run_new_sa
                                _treetable.tree.bind("<Double-1>", _treetable.run_new_sa)
                                _treetable.tree['height'] = 8 if 8 < len(_data) else len(_data)
                                _treetable.pack(expand=YES, fill=BOTH)
                                _app.title("__{}.{}() --> object list(double click to view this struct)".format(struct, s))
                                _app.geometry("300x300")

                            queue.put((create_object_generator, (_data, i, s)))

                    # If the value is not object display it tree.in treetable.
                    if not find_object:
                        def display_objects(return_gen_list, struct, s):
                            '''
                            Display the data (if object not found inside).
                            :param return_gen_list: the data (list/generator)
                            :param struct: the struct
                            :param s: struct name
                            :return:
                            '''
                            app = tk.Toplevel()
                            x = self.relate.winfo_x()
                            y = self.relate.winfo_y()
                            app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
                            headers = [str(x) for x in range(len(return_gen_list[0]))]
                            func_treetable = TreeTable(app, headers=headers, data=return_gen_list)
                            func_treetable.tree['height'] = 22 if 22 < len(return_gen_list) else len(return_gen_list)
                            func_treetable.pack(expand=YES, fill=BOTH)
                            app.title("{}.{}()".format(struct, s))
                            app.geometry("300x300")

                        queue.put((display_objects, (return_gen_list, struct, s)))

                # if the double clicked founction return an object (and not generator of objects) than run struct analyzer to that object.
                elif isinstance(struct, obj.CType):
                    queue.put((run_struct_analyze, (struct.obj_type, struct.obj_offset)))

                # The function return none special vlaue (example: just a string, not object of list) than just display it.
                else:
                    queue.put((messagebox.showinfo, ("{} output:".format(s), "{}".format(str(struct)), ('**kwargs', {'parent':self}))))

            threading.Thread(target=run_function_in_thread, args=(self, function, arguments, s)).start()

        # Get inside some member of this struct (double click on none function option)
        else:
            try:
                struct = obj.Object(struct_type, struct_addr, self.sa_self.kaddr_space)

                # Check if this struct specified address is in the physical layer (usually came from scan plugin that scan the physical layer)
                if not struct or not struct.is_valid():
                    struct = obj.Object(struct_type, struct_addr, self.sa_self.kaddr_space.physical_space(), native_vm=self.sa_self.kaddr_space)
                    if not struct or not struct.is_valid():
                        struct = obj.Object(struct_type, struct_addr, self.sa_self.kaddr_space)

                self.sa_self.parser(struct, 0, 3, s, pMftExp)
            except Exception:
                print '[-] unable to parse this object (addr: {}, type: {})'.format(struct_addr, struct_type)

            data = []
            directories = []

            # Create the data.
            for key in pMftExp.keys():
                if key != "|properties|":

                    my_tup = tuple([0 for i in range(len(self.headers) - 1)])

                    if pMftExp[key].has_key("|properties|"):
                        my_tup = pMftExp[key]["|properties|"]

                    # If this is directory
                    if len(pMftExp[key]) - pMftExp[key].has_key("|properties|") > 0:
                        directories.append(key)
                    my_tup = (key,) + my_tup if type(my_tup) == tuple else (key, str(my_tup))
                    data.append(my_tup)

            # if we able to find something inside this data than go display it.
            if len(data) > 0:

                # Delete all the previews data.
                for i in self.tree.tree.get_children():
                    self.tree.tree.delete(i)
                    self.tree.visual_drag.delete(i)

                # Insert the new data.
                self.tree.insert_items(data)

                # Set the color for directories.
                for i in self.tree.tree.get_children():
                    dir_name = self.tree.tree.item(i, "text")
                    if dir_name in directories:
                        self.tree.SetColorItem(_from_rgb((252, 255, 124)), tag=dir_name)
            else:
                self.current_directory = self.directory_queue.pop()
                self.entry_directory.delete(0, tk.END)
                self.entry_directory.insert(0, self.current_directory)

    def GetDBPointer(self, path, not_case_sensitive=False, return_none_on_bad_path=False):
        '''
        GetDBGPointer hook,
        parse the struct on real time when we go deep inside the struct.
        :param path: GetDBPointer param
        :param not_case_sensitive: GetDBPointer param
        :param return_none_on_bad_path: GetDBPointer param
        :return: GetDBPointer return
        '''
        to_return = Explorer.GetDBPointer(self, path, not_case_sensitive, return_none_on_bad_path)
        path_list = self.current_directory.split("\\")

        # If we already have this information
        if len(path_list) < 3:
            return to_return
        struct_path = ''
        pMftExp = self.dict
        for key in path_list:
            if pMftExp.has_key(key):
                pMftExp = pMftExp[key]
                struct_path += '.{}'.format(key)

        if not pMftExp.has_key('|properties|'):
            return to_return

        # Get chiled structs:
        s = path_list[-1]
        struct_addr = pMftExp['|properties|'][1]
        struct_type = pMftExp['|properties|'][2]
        try:
            struct = obj.Object(struct_type, struct_addr, self.sa_self.kaddr_space)

            # Check if this struct specified address is in the physical layer (usually came from scan plugin that scan the physical layer)
            if not struct or not struct.is_valid():
                struct = obj.Object(struct_addr, struct_type, self.sa_self.kaddr_space.physical_space(), native_vm=self.sa_self.kaddr_space)
                if not struct or not struct.is_valid():
                    struct = obj.Object(struct_addr, struct_type, self.sa_self.kaddr_space)

            self.sa_self.parser(struct, 0, 3, s, pMftExp)
        except Exception:
            pass # Unable to parse some object
        return to_return

class PopUp(tk.Toplevel):
    def __init__(self, options, func_to_call, *args, **kwargs):
        tk.Toplevel.__init__(self, *args, **kwargs)

        # Init variables.
        self.func_to_call = func_to_call
        self.options = options
        self.dict = {}
        self.opts = {}

        # Add all the options to the toplevel.
        for item in options:
            self.dict[item] = ttk.Entry(self)
            ttk.Label(self, text=item, wraplength=500).pack(fill='x')
            self.dict[item].insert(10, options[item])
            self.dict[item].pack(fill='x')

        # Create and pack the button
        self.save_button = ttk.Button(self, text="<- Save & Continue ->", command=self.Save)
        self.save_button.pack(side=tk.BOTTOM)

    def Save(self):
        '''
        This function handle click on the save button.
        :return: None , call the self.func_to_vall(self.opts
        '''

        # Go all over the options and get the data from the textboxs.
        for item in self.options:
            self.opts[item] = self.dict[item].get()

        # Call the function (that should use the arguments)
        self.func_to_call(self.opts)
        self.done = True

class MessagePopUp(tk.Toplevel):
    '''
    Display a message for a couple of seconds.
    '''
    def __init__(self, string_to_show, seconds_to_show=5, related=None, title='Informational', *args, **kwargs):
        tk.Toplevel.__init__(self, *args, **kwargs)

        # Set the title.
        self.title(title)

        # Set the place of this funciton in the screen (if related is specify)
        if related:
            x = related.winfo_x()
            y = related.winfo_y()
            self.geometry("+%d+%d" % (x + ABS_X+150, y + ABS_Y+150))

        # Create and pack the label with the information (string_to_show).
        ttk.Label(self, text=string_to_show).pack(side=tk.LEFT)

        # Destroyd after seconds_to_show.
        self.after(int(seconds_to_show*1000), self.destroy)

class Options(Frame):
    '''
    The Options windows on the start and that pop when we open options from the menu.
    '''
    def __init__(self, master, dict=None, on_start=True, *args, **kwargs):
        Frame.__init__(self, master, *args, **kwargs)
        self.data_order = (
        'Saved File', 'Memory File', 'Memory Profile', 'Dump-Dir', 'KDBG Address (for faster loading)',
        'Show Unnamed Handles', 'Show PE Strings', 'Volatility File Path', 'Virus Total API Key')
        self.on_start = on_start
        self.master = master
        self.user_dict = dict
        self.buttons = {}
        self.all_profiles = registry.get_plugin_classes(obj.Profile).keys()

        self.options = options = {'Saved File': dict['Saved File'] if dict.has_key('Saved File') else '',
                                  'Memory File': dict['Memory File'] if dict.has_key('Memory File') else '',
                                  'Memory Profile': dict['Memory Profile'] if dict.has_key('Memory Profile') and dict['Memory Profile'] in self.all_profiles else '',
                                  'Dump-Dir': dict['Dump-Dir'] if dict.has_key('Dump-Dir') else '',
                                  'KDBG Address (for faster loading)': dict[
                                      'KDBG Address (for faster loading)'] if dict.has_key(
                                      'KDBG Address (for faster loading)') else '',
                                  'Show Unnamed Handles': dict['Show Unnamed Handles'] if dict.has_key(
                                      'Show Unnamed Handles') and dict['Show Unnamed Handles'].lower() in ['true',
                                                                                                           'false'] else 'False',
                                  'Show PE Strings': dict['Show PE Strings'] if dict.has_key('Show PE Strings') and dict['Show PE Strings'].lower() in ['true', 'false'] else 'True',
                                  'Volatility File Path': dict['Volatility File Path'] if dict.has_key(
                                      'Volatility File Path') else (sys.argv[0] if ((
                                          'vol' in sys.argv[0].lower() or 'memtriage' in sys.argv[0].lower()) and not 'volexp' in sys.argv[
                                          0].lower()) else os.getcwd().replace(os.path.join('volatility', 'plugins'),
                                                                               r'{}vol.py'.format(os.sep))) if 'volatility' in os.getcwd().lower() else '',
                                  'Virus Total API Key': dict['Virus Total API Key'] if dict.has_key(
                                      'Virus Total API Key') else ''}
        self.dict = {}
        title = ttk.Label(master, text='Options Menu:', wraplength=500, font=("Courier", 18))
        title.config(anchor="center")
        title.pack(fill='x')
        if on_start:
            ttk.Label(master, text='you must fill all the (*) (or enter .atz file[saved from some run])', wraplength=500,
                     font=("Courier", 14)).pack(fill='x')
        else:
            ttk.Label(master,
                     text='Load a saved .atz file or enter the setting manually:',
                     wraplength=500, font=("Courier", 14)).pack(fill='x')

        # Get Saved File: (*)
        self.dict['Saved File'] = ttk.Entry(master)#, state='normal' if on_start else 'disabled')
        self.buttons['Saved File'] = ttk.Button(master,
                                               text='Saved File [atz file type]',
                                               state='normal' if on_start else 'disabled',
                                               command=lambda: self.get_file('Saved File'))
        self.buttons['Saved File'].pack(fill='x')
        self.dict['Saved File'].insert(10, options['Saved File'] or '')
        self.dict['Saved File'].pack(fill='x')

        # Get Memory File: (*)
        self.dict['Memory File'] = ttk.Entry(master)
        self.buttons['Memory File'] = ttk.Button(master, text='Memory File (*)',
                                                state='normal' if on_start else 'disabled',
                                                command=lambda: self.get_file('Memory File'))
        self.buttons['Memory File'].pack(fill='x')
        self.dict['Memory File'].insert(10, options['Memory File'] or '')
        self.dict['Memory File'].pack(fill='x')

        # Get Memory Profile: (*)
        self.dict['Memory Profile'] = Combobox(master, state="readonly" if on_start else 'disabled', values=self.all_profiles)
        self.buttons['Memory Profile'] = ttk.Button(master, text='Memory Profile (*)', state='normal' if on_start else 'disabled', command=lambda: self.dict['Memory Profile'].tk.call('ttk::combobox::Post', self.dict['Memory Profile']))
        self.buttons['Memory Profile'].pack(fill='x')

        if options['Memory Profile'] != '':
            self.dict['Memory Profile'].current(self.all_profiles.index(options['Memory Profile']))
        self.dict['Memory Profile'].pack(fill='x')

        # Change the color of the disable buttons.
        if not on_start:
            self.dict['Memory File'].config(state='readonly')#, fg='grey50')
            self.dict['Saved File'].config(state='readonly')
            #self.buttons['Memory Profile'].config(fg='grey50')
        else:
            ToolTip(self.buttons['Saved File'], 'Please Enter To Choose an Atz File Type\nThis File Is A Saved File Of This Tool\nThat You Get From Previous Runnings')
            ToolTip(self.buttons['Memory File'], 'Please Enter To Choose Memory File')
            ToolTip(self.buttons['Memory Profile'], 'Please Enter The Profile Of The Memory Image File')

        # Get Dump directory (*)
        self.dict['Dump-Dir'] = ttk.Entry(master)
        self.buttons['Dump-Dir'] = ttk.Button(master, text='Dump-Dir (*)', command=lambda: self.get_dir('Dump-Dir'))
        ToolTip(self.buttons['Dump-Dir'], 'Please Enter To Choose a Dump Directory')
        self.buttons['Dump-Dir'].pack(fill='x')
        self.dict['Dump-Dir'].insert(10, options['Dump-Dir'])
        self.dict['Dump-Dir'].pack(fill='x')

        # Get Volatility File Path (*)
        self.dict['Volatility File Path'] = ttk.Entry(master)
        self.buttons['Volatility File Path'] = ttk.Button(master, text='Volatility File Path (*)',
                                                         command=lambda: self.get_file('Volatility File Path'))
        ToolTip(self.buttons['Volatility File Path'], 'Optional:\nPlease Enter To Choose the Volatility/Memtriage File Path')
        self.buttons['Volatility File Path'].pack(fill='x')
        self.dict['Volatility File Path'].insert(10, options['Volatility File Path'])
        self.dict['Volatility File Path'].pack(fill='x')

        # Get KDBG address (optional)
        self.dict['KDBG Address (for faster loading)'] = ttk.Entry(master)
        self.buttons['KDBG Address (for faster loading)'] = ttk.Label(master,
                                                                     text='KDBG Address (for faster loading)',
                                                                     wraplength=500)
        self.buttons['KDBG Address (for faster loading)'].config(anchor="center")
        ToolTip(self.buttons['KDBG Address (for faster loading)'], 'Optional:\nPlease Enter The KDBG Address')
        self.buttons['KDBG Address (for faster loading)'].pack(fill='x')
        self.dict['KDBG Address (for faster loading)'].insert(10, options[
            'KDBG Address (for faster loading)'])
        self.dict['KDBG Address (for faster loading)'].pack(fill='x')

        # Show\Unshow unnamed handles.:
        self.buttons['Show Unnamed Handles'] = ttk.Label(master, text='Show Unnamed Handles', wraplength=500)
        self.buttons['Show Unnamed Handles'].config(anchor="center")
        ToolTip(self.buttons['Show Unnamed Handles'], 'Please Choose If You Want to See Unnamed Handles')
        self.buttons['Show Unnamed Handles'].pack(fill='x')
        self.dict['Show Unnamed Handles'] = Combobox(master, state="readonly", values=['True', 'False'])
        if self.options['Show Unnamed Handles'].lower() == 'true':
            self.dict['Show Unnamed Handles'].current(0)
        else:
            self.dict['Show Unnamed Handles'].current(1)
        self.dict['Show Unnamed Handles'].pack(fill='x')

        # Show\Unshow PE Strings.:
        self.buttons['Show PE Strings'] = ttk.Label(master, text='Show PE Strings', wraplength=500)
        self.buttons['Show PE Strings'].config(anchor="center")
        ToolTip(self.buttons['Show PE Strings'], 'Please Choose If You Want to Search for Strings in PE File Properties')
        self.buttons['Show PE Strings'].pack(fill='x')
        self.dict['Show PE Strings'] = Combobox(master, state="readonly", values=['True', 'False'])
        if self.options['Show PE Strings'].lower() == 'true':
            self.dict['Show PE Strings'].current(0)
        else:
            self.dict['Show PE Strings'].current(1)
        self.dict['Show PE Strings'].pack(fill='x')

        # Get Virus Total API Key
        self.dict['Virus Total API Key'] = ttk.Entry(master)
        self.buttons['Virus Total API Key'] = ttk.Label(master,
                                                       text='Virus Total API Key (If you want to integrate with virus total) (optional)',
                                                       wraplength=500)
        self.buttons['Virus Total API Key'].config(anchor="center")
        ToolTip(self.buttons['Virus Total API Key'], 'Optional:\nPlease Enter Virus Total API KEY If You Want To Integrate With Virus Total')
        self.buttons['Virus Total API Key'].pack(fill='x')
        self.dict['Virus Total API Key'].insert(10, options['Virus Total API Key'])
        self.dict['Virus Total API Key'].pack(fill='x')

        self.save_button = tk.Button(master, text="<- Save & Continue ->", command=self.Save)
        self.save_button.pack(side=tk.BOTTOM)  # side=tk.LEFT)
        #self.grab_set()

    def get_dir(self, item):
        '''
        Ask for directory using tkFileDialog and set it to the item textbox.
        :param item: textbox item
        :return: None
        '''
        selected = tkFileDialog.askdirectory()
        if selected and selected != '':
            self.options[item] = selected
            self.dict[item].delete(0, 'end')
            self.dict[item].insert(10, self.options[item])

    def get_file(self, item):
        '''
        Ask for file using tkFileDialog and set it to the item textbox.
        :param item: textbox item
        :return: None
        '''
        selected = tkFileDialog.askopenfilename()
        if selected and selected != '':
            self.options[item] = selected
            self.dict[item].delete(0, 'end')
            self.dict[item].insert(10, self.options[item])

    def Save(self):
        '''
        Check arguments and return if they good.
        :return: None
        '''

        # Get all the data from the textboxes.
        for data in self.data_order:
            self.options[data] = self.dict[data].get()

        bad_args = False
        err_msg = ''

        my_arguments = self.options

        # On the start let the user edit more text box (like dump file and profile).
        if self.on_start:
            if os.path.isfile(my_arguments['Saved File']):
                if my_arguments['Saved File'].endswith('atz'):
                    # self.buttons['Saved File'].configure(foreground="black")
                    my_arguments['Saved File'] = os.path.realpath(my_arguments['Saved File'])
                    saved_file = True
                    self.user_dict = self.options
                    self.master.title('Loading Please Wait')
                    for child in self.master.winfo_children():
                        child.destroy()
                    return
                else:
                    # self.buttons['Saved File'].configure(foreground="red")
                    err_msg = "Your saved file must be with .atz extension format (if you start from saved file)\n"

            if not os.path.isfile(my_arguments['Memory File']):
                # self.buttons['Memory File'].configure(foreground="red")
                bad_args = True
                err_msg += "You must specify an existing Memory File\n"
            else:
                my_arguments['Memory File'] = os.path.realpath(my_arguments['Memory File'])
                # self.buttons['Memory File'].configure(foreground="black")

            if not (my_arguments['Memory Profile']):
                # self.buttons['Memory Profile'].configure(foreground="red")
                bad_args = True
                err_msg += "You must specify an existing Memory Profile..\n"
            else:
                pass
                #self.buttons['Memory Profile'].configure(foreground="black")

        if not os.path.exists(my_arguments['Dump-Dir']):
            # self.buttons['Dump-Dir'].configure(foreground="red")
            bad_args = True
            err_msg += "You must specify an existing Dump-Dir\n"
        else:
            my_arguments['Dump-Dir'] = os.path.realpath(my_arguments['Dump-Dir'])
            # self.buttons['Dump-Dir'].configure(foreground="black")

        if not (isinstance(my_arguments['KDBG Address (for faster loading)'], int) or str(my_arguments['KDBG Address (for faster loading)']).isdigit()) and my_arguments[
            'KDBG Address (for faster loading)'] != '':
            # self.buttons['KDBG Address (for faster loading)'].configure(foreground="red")
            bad_args = True
            err_msg += "You must specify the KDBG as an integer\n"
        else:
            pass # self.buttons['KDBG Address (for faster loading)'].configure(foreground="black")

        if not os.path.isfile(my_arguments['Volatility File Path']):
            # self.buttons['Volatility File Path'].configure(foreground="red")
            bad_args = True
            err_msg += "You must specify an existing Volatility File Path\n"
        else:
            my_arguments['Volatility File Path'] = os.path.realpath(my_arguments['Volatility File Path'])
            # self.buttons['Volatility File Path'].configure(foreground="black")

        # Print message if the arguments not good.
        if bad_args:
            print '\a'
            messagebox.showerror("Error", err_msg, parent=self)

        # All the items sets good, set the self.user_dict and destroy the options.
        else:
            self.user_dict = self.options
            self.master.title('Loading Please Wait')
            for child in self.master.winfo_children():
                child.destroy()

class LoadingButton(tk.Button):
    '''
    The load screen a circle that change color.
    '''
    def __init__(self, master, relate, c_button, dont_use_queue=True, *args, **kwargs):

        # Init handle to click on the progressbar.
        c_button.bind("<ButtonRelease-1>", self.display_running)

        # Init Class Variables
        self.c_button = c_button
        self.last = 0
        job_queue.put_alert = self.put_alert
        self.job_data = []
        self.job_data_done = []
        self.dont_use_queue = dont_use_queue
        self.master = master
        self.relate = relate
        self.app = None

        # Start to set the progressbar state.
        self.master.after(500, self.draw)

    def draw(self):
        '''
        This function change the progressbar state.
        :return:
        '''
        self.last = (self.last + 8) % 100
        self.c_button.int_var.set(self.last)
        self.master.after(500, self.draw)

    def put_alert(self, args):
        '''
        This function will wrap the put so everytime we put something we will se that (the progressbar change)
        :param args: args to put in the queue.
        :return: None
        '''
        self.alert()
        job_queue.put(args)

    def alert(self):
        '''
        Call the function (in a thread) that hange the progressbar state to 5 seconds.
        :return: None
        '''
        threading.Thread(target=self.alert_thread).start()

    def alert_thread(self):
        '''
        change the state of the progressbar for 5 seconds.
        :return: None
        '''
        queue.put((self.c_button.config, ({'mode': 'indeterminate', 'style': 'blue.Horizontal.TProgressbar'},)))
        time.sleep(5)
        queue.put((self.c_button.config, ({'mode': 'determinate', 'style': 'Horizontal.TProgressbar'},)))

    def on_exit(self, event=None):
        '''
        Exit the program and set the app to none
        :param event: event
        :return: None
        '''
        self.app.destroy()
        self.app = None

    def display_running(self, event=None):
        '''
        This fucntion display a toplevel with a table of all the running jobs.
        :param event:
        :return:
        '''
        # Bring the job information to the top and return (if exist) else display it
        if self.app:
            self.app.attributes('-topmost', 1)
            self.app.attributes('-topmost', 0)
            return

        # Create the toplevel
        self.app = tk.Toplevel()
        self.app.protocol("WM_DELETE_WINDOW", self.on_exit)
        x = self.relate.winfo_x()
        y = self.relate.winfo_y()
        self.app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
        self.app.geometry("900x620")
        self.app.title('Volexp Job Information')

        # Create the frames inside paned view
        self.pw = PanedWindow(self.app, orient='vertical')
        top_frame = ttk.Frame(self.pw)
        bot_frame = ttk.Frame(self.pw)

        # Create the top Frame
        label = ttk.Label(top_frame, text="Here you can get information about tasks that are currently running.")
        label.pack(side="top", fill="x", pady=10)
        headers = ("Job ID", "Job Name", "Job Args", "Job Status", "Job Start Time")
        data = [(str(item[0]).replace('.', ''),) + item[1:] + (time.ctime(item[0]),) for item in self.job_data]
        self.treetable = TreeTable(top_frame, headers=headers, data=data)
        self.treetable.pack(expand=YES, fill=BOTH)
        self.pw.add(top_frame)

        # Create the bot Frame
        label = ttk.Label(bot_frame, text="Here you can get information about tasks that this finished running.")
        label.pack(side="top", fill="x", pady=10)
        headers = ("Job ID", "Job Name", "Job Args", "Job Status", "Job Start Time")
        job_data_done = [(str(item[0]).replace('.', ''),) + item[1:] + (time.ctime(item[0]),) for item in self.job_data_done]
        self.treetable_done = TreeTable(bot_frame, headers=headers, data=job_data_done)
        self.treetable_done.pack(expand=YES, fill=BOTH)
        self.pw.add(bot_frame)

        # Pack the data.
        top_frame.pack(side=TOP, fill=BOTH)
        bot_frame.pack(side=TOP, fill=BOTH)
        self.pw.pack(side=TOP, fill=BOTH)
        self.refresh_button = ttk.Button(self.app, text='Refresh', command=self.refresh_data)
        self.refresh_button.pack(fill='x')
        self.app.bind('<F5>', self.refresh_data)

        # Add new data
        self.refresh_data()

    def refresh_data(self, event=None):
        '''
        This function refresh the tree data with new item
        :return: None
        '''

        # Go all over the queue to get new items (and remove old)
        while not job_queue.empty():
            item = job_queue.get()

            # If job finish remove it from the self.job_data list
            if item[-1] != 'Running':

                # Remove the job by his id (item[1] is the id) and add him to the done job list.
                self.job_data_done = self.job_data_done + [c_item[:-1] + (item[-1],) for c_item in self.job_data if str(c_item[0]) == str(item[0])]
                self.job_data = [c_item for c_item in self.job_data if str(c_item[0]) != str(item[0])]
            else:
                self.job_data.append(item)

        # Refresh the job running table
        data = [(str(item[0]).replace('.', ''),) + item[1:] + (time.ctime(item[0]),) for item in self.job_data]
        for i in self.treetable.tree.get_children():
            self.treetable.tree.delete(i)
            self.treetable.visual_drag.delete(i)
        self.treetable.insert_items(data)

        # Refresh the job done table
        done_data = [(str(item[0]).replace('.', ''),) + item[1:] + (time.ctime(item[0]),) for item in self.job_data_done]
        for i in self.treetable_done.tree.get_children():
            self.treetable_done.tree.delete(i)
            self.treetable_done.visual_drag.delete(i)
        self.treetable_done.insert_items(done_data)

# Delete unuse functions
class LoadingScreen(Frame):
    '''
    The load screen a circle that change color.
    '''
    def __init__(self, master, dont_use_queue=True, *args, **kwargs):
        Frame.__init__(self, master, *args, **kwargs)
        self.my_frame = Frame(master=master)
        self.my_frame.pack()
        self.dont_use_queue=dont_use_queue
        self.master = master
        self.canvas = tk.Canvas(master=self.my_frame, width=500, height=500)
        self.canvas.pack()
        self.colors = ['snow', 'ghost white', 'white smoke', 'gainsboro', 'floral white', 'old lace',
    'linen', 'antique white', 'papaya whip', 'blanched almond', 'bisque', 'peach puff',
    'navajo white', 'lemon chiffon', 'mint cream', 'azure', 'alice blue', 'lavender',
    'lavender blush', 'misty rose', 'dark slate gray', 'dim gray', 'slate gray',
    'light slate gray', 'gray', 'light grey', 'midnight blue', 'navy', 'cornflower blue', 'dark slate blue',
    'slate blue', 'medium slate blue', 'light slate blue', 'medium blue', 'royal blue',  'blue',
    'dodger blue', 'deep sky blue', 'sky blue', 'light sky blue', 'steel blue', 'light steel blue',
    'light blue', 'powder blue', 'pale turquoise', 'dark turquoise', 'medium turquoise', 'turquoise',
    'cyan', 'light cyan', 'cadet blue', 'medium aquamarine', 'aquamarine', 'dark green', 'dark olive green',
    'dark sea green', 'sea green', 'medium sea green', 'light sea green', 'pale green', 'spring green',
    'lawn green', 'medium spring green', 'green yellow', 'lime green', 'yellow green',
    'forest green', 'olive drab', 'dark khaki', 'khaki', 'pale goldenrod', 'light goldenrod yellow',
    'light yellow', 'yellow', 'gold', 'light goldenrod', 'goldenrod', 'dark goldenrod', 'rosy brown',
    'indian red', 'saddle brown', 'sandy brown',
    'dark salmon', 'salmon', 'light salmon', 'orange', 'dark orange',
    'coral', 'light coral', 'tomato', 'orange red', 'red', 'hot pink', 'deep pink', 'pink', 'light pink',
    'pale violet red', 'maroon', 'medium violet red', 'violet red',
    'medium orchid', 'dark orchid', 'dark violet', 'blue violet', 'purple', 'medium purple',
    'thistle', 'snow2', 'snow3',
    'snow4', 'seashell2', 'seashell3', 'seashell4', 'AntiqueWhite1', 'AntiqueWhite2',
    'AntiqueWhite3', 'AntiqueWhite4', 'bisque2', 'bisque3', 'bisque4', 'PeachPuff2',
    'PeachPuff3', 'PeachPuff4', 'NavajoWhite2', 'NavajoWhite3', 'NavajoWhite4',
    'LemonChiffon2', 'LemonChiffon3', 'LemonChiffon4', 'cornsilk2', 'cornsilk3',
    'cornsilk4', 'ivory2', 'ivory3', 'ivory4', 'honeydew2', 'honeydew3', 'honeydew4',
    'LavenderBlush2', 'LavenderBlush3', 'LavenderBlush4', 'MistyRose2', 'MistyRose3',
    'MistyRose4', 'azure2', 'azure3', 'azure4', 'SlateBlue1', 'SlateBlue2', 'SlateBlue3',
    'SlateBlue4', 'RoyalBlue1', 'RoyalBlue2', 'RoyalBlue3', 'RoyalBlue4', 'blue2', 'blue4',
    'DodgerBlue2', 'DodgerBlue3', 'DodgerBlue4', 'SteelBlue1', 'SteelBlue2',
    'SteelBlue3', 'SteelBlue4', 'DeepSkyBlue2', 'DeepSkyBlue3', 'DeepSkyBlue4',
    'SkyBlue1', 'SkyBlue2', 'SkyBlue3', 'SkyBlue4', 'LightSkyBlue1', 'LightSkyBlue2',
    'LightSkyBlue3', 'LightSkyBlue4', 'SlateGray1', 'SlateGray2', 'SlateGray3',
    'SlateGray4', 'LightSteelBlue1', 'LightSteelBlue2', 'LightSteelBlue3',
    'LightSteelBlue4', 'LightBlue1', 'LightBlue2', 'LightBlue3', 'LightBlue4',
    'LightCyan2', 'LightCyan3', 'LightCyan4', 'PaleTurquoise1', 'PaleTurquoise2',
    'PaleTurquoise3', 'PaleTurquoise4', 'CadetBlue1', 'CadetBlue2', 'CadetBlue3',
    'CadetBlue4', 'turquoise1', 'turquoise2', 'turquoise3', 'turquoise4', 'cyan2', 'cyan3',
    'cyan4', 'DarkSlateGray1', 'DarkSlateGray2', 'DarkSlateGray3', 'DarkSlateGray4',
    'aquamarine2', 'aquamarine4', 'DarkSeaGreen1', 'DarkSeaGreen2', 'DarkSeaGreen3',
    'DarkSeaGreen4', 'SeaGreen1', 'SeaGreen2', 'SeaGreen3', 'PaleGreen1', 'PaleGreen2',
    'PaleGreen3', 'PaleGreen4', 'SpringGreen2', 'SpringGreen3', 'SpringGreen4',
    'green2', 'green3', 'green4', 'chartreuse2', 'chartreuse3', 'chartreuse4',
    'OliveDrab1', 'OliveDrab2', 'OliveDrab4', 'DarkOliveGreen1', 'DarkOliveGreen2',
    'DarkOliveGreen3', 'DarkOliveGreen4', 'khaki1', 'khaki2', 'khaki3', 'khaki4',
    'LightGoldenrod1', 'LightGoldenrod2', 'LightGoldenrod3', 'LightGoldenrod4',
    'LightYellow2', 'LightYellow3', 'LightYellow4', 'yellow2', 'yellow3', 'yellow4',
    'gold2', 'gold3', 'gold4', 'goldenrod1', 'goldenrod2', 'goldenrod3', 'goldenrod4',
    'DarkGoldenrod1', 'DarkGoldenrod2', 'DarkGoldenrod3', 'DarkGoldenrod4',
    'RosyBrown1', 'RosyBrown2', 'RosyBrown3', 'RosyBrown4', 'IndianRed1', 'IndianRed2',
    'IndianRed3', 'IndianRed4', 'sienna1', 'sienna2', 'sienna3', 'sienna4', 'burlywood1',
    'burlywood2', 'burlywood3', 'burlywood4', 'wheat1', 'wheat2', 'wheat3', 'wheat4', 'tan1',
    'tan2', 'tan4', 'chocolate1', 'chocolate2', 'chocolate3', 'firebrick1', 'firebrick2',
    'firebrick3', 'firebrick4', 'brown1', 'brown2', 'brown3', 'brown4', 'salmon1', 'salmon2',
    'salmon3', 'salmon4', 'LightSalmon2', 'LightSalmon3', 'LightSalmon4', 'orange2',
    'orange3', 'orange4', 'DarkOrange1', 'DarkOrange2', 'DarkOrange3', 'DarkOrange4',
    'coral1', 'coral2', 'coral3', 'coral4', 'tomato2', 'tomato3', 'tomato4', 'OrangeRed2',
    'OrangeRed3', 'OrangeRed4', 'red2', 'red3', 'red4', 'DeepPink2', 'DeepPink3', 'DeepPink4',
    'HotPink1', 'HotPink2', 'HotPink3', 'HotPink4', 'pink1', 'pink2', 'pink3', 'pink4',
    'LightPink1', 'LightPink2', 'LightPink3', 'LightPink4', 'PaleVioletRed1',
    'PaleVioletRed2', 'PaleVioletRed3', 'PaleVioletRed4', 'maroon1', 'maroon2',
    'maroon3', 'maroon4', 'VioletRed1', 'VioletRed2', 'VioletRed3', 'VioletRed4',
    'magenta2', 'magenta3', 'magenta4', 'orchid1', 'orchid2', 'orchid3', 'orchid4', 'plum1',
    'plum2', 'plum3', 'plum4', 'MediumOrchid1', 'MediumOrchid2', 'MediumOrchid3',
    'MediumOrchid4', 'DarkOrchid1', 'DarkOrchid2', 'DarkOrchid3', 'DarkOrchid4',
    'purple1', 'purple2', 'purple3', 'purple4', 'MediumPurple1', 'MediumPurple2',
    'MediumPurple3', 'MediumPurple4', 'thistle1', 'thistle2', 'thistle3', 'thistle4',
    'gray1', 'gray2', 'gray3', 'gray4', 'gray5', 'gray6', 'gray7', 'gray8', 'gray9', 'gray10',
    'gray11', 'gray12', 'gray13', 'gray14', 'gray15', 'gray16', 'gray17', 'gray18', 'gray19',
    'gray20', 'gray21', 'gray22', 'gray23', 'gray24', 'gray25', 'gray26', 'gray27', 'gray28',
    'gray29', 'gray30', 'gray31', 'gray32', 'gray33', 'gray34', 'gray35', 'gray36', 'gray37',
    'gray38', 'gray39', 'gray40', 'gray42', 'gray43', 'gray44', 'gray45', 'gray46', 'gray47',
    'gray48', 'gray49', 'gray50', 'gray51', 'gray52', 'gray53', 'gray54', 'gray55', 'gray56',
    'gray57', 'gray58', 'gray59', 'gray60', 'gray61', 'gray62', 'gray63', 'gray64', 'gray65',
    'gray66', 'gray67', 'gray68', 'gray69', 'gray70', 'gray71', 'gray72', 'gray73', 'gray74',
    'gray75', 'gray76', 'gray77', 'gray78', 'gray79', 'gray80', 'gray81', 'gray82', 'gray83',
    'gray84', 'gray85', 'gray86', 'gray87', 'gray88', 'gray89', 'gray90', 'gray91', 'gray92',
    'gray93', 'gray94', 'gray95', 'gray97', 'gray98', 'gray99']
        self.t = turtle.RawTurtle(self.canvas)
        self.t.pencolor("#ff0000") # Red
        self.t.turtlesize(0)
        self.t.width(6)
        self.size = 20
        self.t.penup()
        self.t.goto(-25, -0)
        self.t.pendown()
        self.t.write("      Atz\nLoad Screen")
        self.t.penup()
        self.t.goto(0,-80)
        self.t.pendown()

        # Draw the circle.
        if self.dont_use_queue:
            self.master.after(500, self.draw)

    def draw(self):
        '''
        This function keep draw the circle
        :return:
        '''
        # if the windows is destroy in one thread but this function is not destroy yet.
        try:
            self.t.pencolor(random.choice(self.colors))
        except tk.TclError:
            return
        self.t.circle(100)
        if self.dont_use_queue:
            self.master.after(500, self.draw)

# Add add tab function
class NoteBook(ttk.Notebook):
    '''
    NoteBook with the menu that let as to remove tabs.
    '''
    def __init__(self, master, *args, **kwargs):
        ttk.Notebook.__init__(self, master, *args, **kwargs)
        self.aMenu = tk.Menu(root, tearoff=0)
        self.aMenu.add_command(label='Close Tab', command=self.close_tab)
        self.aMenu.add_command(label='Close All Tabs To The Right', command=self.close_right_tabs)
        #self.aMenu.add_command(label='Attach To Main', command=self.attach) # TODO
        self.bind(right_click_event, self.on_click)
        self.enable_traversal()

    def attach(self):
        '''
        This function let the user draganddrop support from one notebook the mainscreen notebook.
        :return: None
        '''
        global root
        nb = root.NoteBook
        event = self.aMenu.c_event
        tab_name = self.tab(self.tk.call(self._w, "identify", "tab", event.x, event.y), "text")

        """
        if event.widget.identify(event.x, event.y) == 'label':
            index = event.widget.index('@%d,%d' % (event.x, event.y))
            print event.widget.tab(index, 'text')
        """

    def close_right_tabs(self):
        '''
        Close all the tabs from the right
        :return:
        '''

        event = self.aMenu.c_event

        # Try to get the clicked tab (some tkinter version don't support this operation < 8.4)
        try:
            clicked_tab = self.tk.call(self._w, "identify", "tab", event.x, event.y)
        except tk.TclError:
            return # Unsupported Tk Version

        active_tab = self.index(self.select())

        # Make sure that the first tab is never closed.
        if clicked_tab != 0:
            self.aMenu.unpost()

        # Go all over the tabs
        for tab in self.tabs():
            tab = self.index(tab)
            if clicked_tab < tab:

                # Check if the selection is a tab or none tab
                if tab != 0:

                    # Move the current tab selection 1 back.
                    if tab == active_tab:
                        self.select(tab - 1)
                    self.forget(tab)
                else:
                    print '[-] The first tab cannot be removed'

    def close_tab(self):
        '''
        Close a specific tab.
        :return: None
        '''

        event = self.aMenu.c_event

        # Try to get the clicked tab (some tkinter version don't support this operation < 8.4)
        try:
            clicked_tab = self.tk.call(self._w, "identify", "tab", event.x, event.y)
        except tk.TclError:
            return # Unsupported Tk Version

        active_tab = self.index(self.select())

        # Check if the selection is not the first tab (a double check).
        if clicked_tab != 0:
            self.aMenu.unpost()

            # Move the current tab selection 1 back.
            if clicked_tab == active_tab:
                self.select(clicked_tab - 1)
            self.forget(clicked_tab)
        else:
            print '[-] The first tab cannot be removed'

    def popup(self, event):
        '''
        Popup the menu.
        :param event: event
        :return: None
        '''
        self.aMenu.c_event = event
        self.aMenu.tk_popup(event.x_root, event.y_root)

    def on_click(self, event):
        '''
        Right click event.
        :param event: event
        :return: None
        '''

        # Try to get the clicked tab (some tkinter version don't support this operation < 8.4)
        try:
            clicked_tab = self.tk.call(self._w, "identify", "tab", event.x, event.y)
        except tk.TclError:
            return # Unsupported Tk Version

        # Popup the menu if a we press on a tab (and not the first one).
        if clicked_tab != '' and clicked_tab != 0:
            self.popup(event)

class ServicesAll(Frame):
    '''
    all the services as treetable(treeview).
    '''
    def __init__(self, master, resize=True, *args, **kwargs):
        Frame.__init__(self, master, *args, **kwargs)
        data = []
        headers = ('offset','order','start','pid','service name','display name','type','state','binary')

        # Go all over the service dict and add to the data.
        for pid in service_dict:

            # Go all over the services inside this pid.
            for svc in service_dict[pid]:
                data.append(svc)

        # Create and pack the table.
        tree = TreeTable(self, headers=headers, data=data, text_by_item=1, resize=resize)
        tree.tree['height'] = 22 if 22 < len(data) else len(data)
        tree.pack(expand=YES, fill=BOTH)

class Search(tk.Toplevel):
    '''
    Search for all the process main tabs.
    '''
    def __init__(self, lower_table, main_table, headers, *args, **kwargs):
        tk.Toplevel.__init__(self, *args, **kwargs)

        # Put it in the right position
        x = root.winfo_x()
        y = root.winfo_y()
        self.geometry("+%d+%d" % (x + ABS_X+444, y + ABS_Y))

        # Init class variables
        self.headers = headers
        self.lower_table = lower_table
        self.main_table = main_table

        # Create and pack the tables.
        self.search_text = tk.Entry(self)
        self.search_text.insert(10, 'Search text here')
        self.search_text.bind("<Return>", self.search)
        self.search_text.pack(fill='x')
        self.search_button = tk.Button(self, text="<- Search ->", command=self.search)
        self.search_button.pack(fill='x')
        self.tree = TreeTable(self, headers=headers, data=[], text_by_item=1, resize=True)
        self.tree.pack(expand=YES, fill=BOTH)
        self.tree.tree.bind("<Return>", self.OnDoubleClick)
        self.tree.tree.bind("<Double-1>", self.OnDoubleClick)
        self.search_text.bind("<FocusIn>", self.focus_in)
        self.search_text.focus()

    def focus_in(self, event=None):
        '''
        This function handle focus_in event in the textbox and mark the textbox.
        :param event: None
        :return: None
        '''
        self.search_text.selection_range(0, tk.END)

    def OnDoubleClick(self, event):
        '''
        This function go to the double clicked result.
        :param event: None
        :return: None.
        '''
        # Double click on table header to resize
        if event and event.y < 25 and event.y > 0:
            try:
                if self.tree.tree.identify_region(event.x, event.y) == 'separator':
                    self.tree.resize_col(self.tree.tree.identify_column(event.x))
                return
            except tk.TclError:
                return
        # Double click where no item selected
        elif len(self.tree.tree.selection()) == 0 :
            return

        global root

        item = self.tree.tree.selection()[0]
        selected_pid = int(self.tree.tree.item(item,"text"))

        # Get all the items from the processes tables
        for row in self.main_table.get_all_children(self.main_table.tree):
            row = row[0]

            # check that the item is valid.
            if self.main_table.tree.item(row).has_key('values'):

                # Check if this item is the selected pid (to go to).
                if int(self.main_table.tree.item(row)['values'][self.main_table.text_by_item]) == selected_pid:

                    # Select the right process and open the lower pane.
                    self.main_table.tree.focus(row)
                    self.main_table.tree.selection_set(row)
                    self.main_table.tree.see(row)
                    root.lift()

                    # Go to the specific dll (if this is dll).
                    if self.tree.tree.item(item)['values'][2] == "DLL":
                        self.main_table.show_lower_pane("Dlls")
                        self.lower_table = self.main_table.lower_table
                        for ht_row in self.lower_table.dlls_table.tree.get_children():
                            if self.lower_table.dlls_table.tree.item(ht_row)['values'][3] == self.tree.tree.item(item)['values'][3]:
                                self.lower_table.dlls_table.tree.focus(ht_row)
                                self.lower_table.dlls_table.tree.selection_set(ht_row)
                                self.lower_table.dlls_table.tree.see(ht_row)

                    # Go to the specific handle (if this is handle).
                    else:
                        self.main_table.show_lower_pane("Handles")
                        self.lower_table = self.main_table.lower_table
                        for ht_row in self.lower_table.handles_table.tree.get_children():
                            if self.lower_table.handles_table.tree.item(ht_row)['values'][1] == self.tree.tree.item(item)['values'][3]:
                                self.lower_table.handles_table.tree.focus(ht_row)
                                self.lower_table.handles_table.tree.selection_set(ht_row)
                                self.lower_table.handles_table.tree.see(ht_row)
                    break

    def search(self, event=None):
        '''
        Serach for the specifig item inside the process_handles and process_dlls.
        :param event: None
        :return: None
        '''
        global process_dlls
        global process_handles
        global process_bases
        global volself

        text_to_search = self.search_text.get().lower()
        data = []
        print "[+] searching for: {}".format(text_to_search)
        # Remove previouse searched items.
        for i in self.tree.tree.get_children():
            self.tree.tree.delete(i)
            self.tree.visual_drag.delete(i)

        # Search for handles and dlls.
        for pid in process_dlls:

            # Go all over the handles.
            if process_handles.has_key(pid):
                for tup in process_handles[pid]:
                    if text_to_search in tup[1].lower():
                        e_proc = process_bases[pid]["proc"]
                        item = (e_proc.ImageFileName, pid) + tup
                        data.append(item)
                        #self.tree.tree.insert('', END, values=item, text=item[1])

            # Go all over the dlls.
            for tup in process_dlls[pid]:
                if text_to_search in tup.lower():
                    e_proc = process_bases[pid]["proc"]
                    item = (e_proc.ImageFileName, pid, "DLL", tup)
                    data.append(item)
                    #self.tree.tree.insert('', END, values=item, text=item[1])

        self.tree.insert_items(data)

class CmdPlugin(tk.Toplevel):
    '''
    Create a cmd like for running plugins in gui.
    '''
    def __init__(self, plugin_name, vol_path, plugins_path, file_path, profile,  *args, **kwargs):
        tk.Toplevel.__init__(self, *args, **kwargs)
        self.headers = ('Result',)

        # Set the self.default_plugin according to if this is running under memtriage/volatility.
        if profile and file_path:
            self.default_plugin = r'"{}" "{}" --plugins="{}" -f "{}" --profile={} {}'.format(sys.executable, vol_path, plugins_path, file_path, profile, plugin_name)
        else:
            self.default_plugin = r'"{}" "{}" --plugins={}'.format(sys.executable, vol_path, plugin_name)

        # Init and pack all the class gui, with tooltips.
        self.search_text = tk.Entry(self)
        self.search_text.insert(10, self.default_plugin)
        self.search_text.xview_moveto(1)
        self.search_text.bind("<Return>",self.run)
        self.search_text.pack(fill='x')
        self.running = False
        frame_line = ttk.Frame(self)
        self.run_button = ttk.Button(frame_line, text="Run-->>>", command=lambda: self.run(None))
        ToolTip(self.run_button, 'Run This Plugin')
        self.clear_button = ttk.Button(frame_line, text="Clear Screen", command=lambda: self.clear(None))
        ToolTip(self.clear_button, 'Clean Table From All the Rows')
        self.apply_button = ttk.Button(frame_line, text="Apply (on properties)", command=lambda: self.apply(None))
        ToolTip(self.apply_button, 'Adds The Output of the Last Used Plugin Run\nAs a New Tab for Each Affected Process')
        self.cb = ttk.Checkbutton(frame_line, text='Alert processes (Ctrl+U to unalert)', state='selected')
        if 'alternate' in self.cb.state():
            self.cb.state(('!alternate',))
        self.cb.state(['selected'])
        ToolTip(self.cb, 'If "Apply" is Checked,\nLight Up All Affected Processes (in the main tab)\nCtrl+U To Stop (or view->unalert all)')
        self.apply_button.pack(side=LEFT)
        self.cb.pack(side=LEFT)
        self.run_button.pack(side=RIGHT)
        self.clear_button.pack(side=RIGHT)
        frame_line.pack(fill='x')
        self.data = []
        self.tree = TreeTable(self, headers=self.headers, data=self.data, text_by_item=0, resize=True)
        self.tree.tree['height'] = 22
        self.tree.pack(expand=YES, fill=BOTH)

    def apply(self, event):
        '''
        This funciton handle apply button press, its apply the data to the specific process propeties.
        :param event:
        :return:
        '''
        global plugins_output

        apply_header = tkSimpleDialog.askstring(title="Apply Header", prompt="Please enter the tab name for this appliance:", parent=self)

        # Check if the user cancel.
        if not apply_header:
            return

        c_pid = None
        c_data = ''
        data_dict = {pid:'' for pid in process_performance}
        for row in self.data:
            row = row[0]
            writed = False

            # Search for new pid to apply.
            for pid in process_performance:
                if ' {} '.format(pid) in row or 'id: {}'.format(pid) in row.lower():

                    # Aplly the last pid data(if any)
                    if c_pid:

                        # Pad data between 2 result with \n---...---\n
                        if data_dict[c_pid] != '':
                            data_dict[c_pid] += '\n'
                            data_dict[c_pid] += '|-|'*180
                            data_dict[c_pid] += '\n'
                        data_dict[c_pid] += c_data

                    c_pid = int(pid)
                    c_data = row
                    writed = True

            if not writed:
                c_data += '\n{}'.format(row)

        pid_list = []
        for c_pid in data_dict:
            if data_dict[c_pid] != '':
                pid_list.append(c_pid)
                if not plugins_output.has_key(c_pid):
                    plugins_output[c_pid] = []
                plugins_output[c_pid].append((apply_header, data_dict[c_pid]))

        # Alert all the processes that have new tabs if the user want to (checkbox state is selected)
        if self.cb.state() == ('selected',):
            main_table.set_processes_alert(pid_list)

    def run(self, event):
        '''
        Call a thread to run the plugin.
        :param event: None
        :return: None
        '''

        # Validate that no other plugin is running and if so alert the user and exit.
        if self.running:
            queue.put((messagebox.showinfo, ("Informational", "There is already an running plugin...", ('**kwargs', {'parent': self}))))
            return
        self.running = True
        self.default_plugin = self.search_text.get()
        t = threading.Thread(target=self.insert_item_thread)
        time.sleep(1)
        t.start()

    def clear(self, event):
        '''
        Clear the screen from all the previews results.
        :param event: None
        :return: None
        '''

        # Delete all the rows.
        for i in self.tree.tree.get_children():
            self.tree.tree.delete(i)
            self.tree.visual_drag.delete(i)

    def insert_item_thread(self):
        '''
        This function run the plugin and append the result.
        :return: None
        '''
        if self.default_plugin == '':
            return
        print '[+] run:', self.default_plugin

        # Add to job queue
        id = time.time()
        job_queue.put_alert((id, 'Run Cmd Plugin', self.default_plugin, 'Running'))

        try:
            output = subprocess.check_output(self.default_plugin)
        except (subprocess.CalledProcessError, OSError, EOFError):
            output = subprocess.Popen([self.default_plugin], shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = output.communicate()[0]
        self.running = False

        # Validate output.
        if 'ERROR' in output:
            queue.put((messagebox.showerror, ("Error", "This plugin failed in runtime with this error:\n{}".format(output), ('**kwargs', {'parent': self}))))
            return
        elif output == '':
            queue.put((messagebox.showinfo, ("Informational", "This plugin returned nothing.", ('**kwargs', {'parent': self}))))
            return

        print output
        self.data = [(item,) for item in output.splitlines()]

        def try_insert_data():
            try:
                self.tree.insert_items(self.data)
            except tk.TclError:
                messagebox.showinfo('Plugin Finish Running', 'You exit the CmdPlugin window but you can still view the output in your shell.')
        queue.put((try_insert_data, ()))
        job_queue.put_alert((id, 'Run Cmd Plugin', self.default_plugin, 'Done'))

class About(tk.Toplevel):
    '''
    This is the about page
    '''
    def __init__(self, img, *args, **kwargs):
        tk.Toplevel.__init__(self, *args, **kwargs)

        # Place the toplevel in the screen, set a title and make it not resizeable.
        x = root.winfo_x()
        y = root.winfo_y()
        self.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
        self.title("About Volatility Explorer")
        self.resizable(False, False)

        # Create the image and data frames.
        image_frame = ttk.Frame(self)
        about_frame = ttk.Frame(self)

        # Insert all the data to the toplevel and pack it.
        ttk.Label(image_frame, image=img).pack()
        ttk.Label(about_frame, text="Volatility Explorer\nCreator: Aviel Zohar\nContact: memoryforensicsanalysis@gmail.com", compound=tk.CENTER).pack(side=TOP)
        git_link = ttk.Label(about_frame, text="Go To Github", foreground='blue', compound=tk.CENTER)
        ToolTip(git_link, r"https://github.com/memoryforensics1/VolExp")
        git_link.bind("<Button-1>", lambda e: open_new(r"https://github.com/memoryforensics1/VolExp"))
        git_link.pack(side=TOP)
        ttk.Label(about_frame, text=CREDITS, compound=tk.CENTER).pack(side=BOTTOM)
        image_frame.pack(side=LEFT)
        about_frame.pack(side=LEFT)

class ToolTip(object):
    '''
    the square that apeare when we on widget.
    '''
    def __init__(self, widget, text='help message'):
        # Init Class Variables.
        self.widget = widget
        self.text = text
        self.tipwindow = None
        self.id = None
        self.x = self.y = 0

        # Event Binding.
        self.widget.bind("<Enter>", self.showtip)
        self.widget.bind("<Leave>", self.hidetip)
        self.widget.bind("<Button-1>", self.hidetip)


    def showtip(self, event=None):
        '''
        Display text in tooltip window (on Enter).
        :param event: None
        :return: None
        '''
        self.event = event
        if self.tipwindow or not self.text:
            return

        # Place the tooltip.
        x, y, cx, cy = self.event.x, self.event.y, self.event.x, self.event.y
        x = x + self.widget.winfo_rootx()+10
        y = cy + self.widget.winfo_rooty()+10
        self.tipwindow = tw = tk.Toplevel()

        # Put the text and pack the tooltip.
        tw.wm_overrideredirect(1)
        tw.wm_geometry("+%d+%d" % (x, y))
        label = tk.Label(tw, text=self.text, justify=LEFT,
                      background="#ffffe0", relief=SOLID, borderwidth=1,
                      font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hidetip(self, event=None):
        '''
        Hide the tip (on leave).
        :param event: None
        :return: None
        '''
        tw = self.tipwindow
        self.tipwindow = None

        # Destroy the tooltip if exist.
        if tw:
            tw.destroy()

class TreeToolTip(object):
    '''
    the square that apeare when we on Treetable(treeview) item.
    '''
    def __init__(self, widget, event):
        self.widget = widget
        self.event = event
        self.tipwindow = None
        self.id = None
        self.x = self.y = 0

    def showtip(self, text):
        '''
        Display text in tooltip window (on Enter).
        :param text: text to display
        :return: None
        '''

        self.text = text
        if self.tipwindow or not self.text:
            return

        # Place and pack the tooltip.
        x, y, cx, cy = self.event.x, self.event.y, self.event.x, self.event.y#self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx()+10# + 57#self.widget.x_root + 57
        y = cy + self.widget.winfo_rooty()+10# +27# find the real one.self.widget.y_root + 27
        self.tipwindow = tw = tk.Toplevel()
        tw.wm_overrideredirect(1)
        tw.wm_geometry("+%d+%d" % (x, y))
        label = tk.Label(tw, text=self.text, justify=LEFT,
                      background="#ffffe0", relief=SOLID, borderwidth=1,
                      font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hidetip(self):
        '''
        Hide the tip (on leave).
        :return: None
        '''
        tw = self.tipwindow
        self.tipwindow = None
        if tw:
            tw.destroy()

class DragAndDropListbox(tk.Listbox):
    ''' A tk listbox with drag'n'drop reordering of entries. '''
    def __init__(self, master, **kw):
        kw['selectmode'] = tk.MULTIPLE
        kw['activestyle'] = 'none'
        tk.Listbox.__init__(self, master, kw)
        self.bind('<Button-1>', self.getState, add='+')
        self.bind('<Button-1>', self.setCurrent, add='+')
        self.bind('<B1-Motion>', self.shiftSelection)
        self.curIndex = None
        self.curState = None

    def setCurrent(self, event):
        ''' gets the current index of the clicked item in the listbox '''
        self.curIndex = self.nearest(event.y)

    def getState(self, event):
        ''' checks if the clicked item in listbox is selected '''
        i = self.nearest(event.y)
        self.curState = self.selection_includes(i)

    def shiftSelection(self, event):
        ''' shifts item up or down in listbox '''
        i = self.nearest(event.y)
        if self.curState == 1:
            self.selection_set(self.curIndex)
        else:
            self.selection_clear(self.curIndex)
        if i < self.curIndex:
            # Moves up
            x = self.get(i)
            selected = self.selection_includes(i)
            self.delete(i)
            self.insert(i+1, x)
            if selected:
                self.selection_set(i+1)
            self.curIndex = i
        elif i > self.curIndex:
        # Moves down
            x = self.get(i)
            selected = self.selection_includes(i)
            self.delete(i)
            self.insert(i-1, x)
            if selected:
                self.selection_set(i-1)
            self.curIndex = i

class MoveLists(tk.Toplevel):
    '''
    2 list box that can move item between them
    '''
    def __init__(self, display, hide, func, *args, **kwargs):
        tk.Toplevel.__init__(self, *args, **kwargs)
        self.display = display
        self.hide = hide
        self.func = func

        frame = Frame(self)
        frame2 = Frame(self)

        frame3 = Frame(frame)
        frame4 = Frame(frame2)

        self.tree1 = DragAndDropListbox(frame3)
        self.tree1.bind("<ButtonRelease-1>", self.update_table)

        self.tree2 = tk.Listbox(frame4, selectmode=tk.MULTIPLE)

        # Insert All the headers to the right tree
        for dis in self.display:
            self.tree1.insert(END, dis)

        for hid in self.hide:
            self.tree2.insert(END, hid)

        button1 = ttk.Button(self, text="<- Move Selected ->", command=self.move_table)

        # Pack it all
        button1.pack(padx=10, fill="x", side=tk.BOTTOM)
        ttk.Label(frame, text='Display Columns').pack(side=tk.TOP)
        ttk.Label(frame2, text='Hide Columns').pack(side=tk.TOP)
        frame3.pack(fill=tk.BOTH)
        frame4.pack(fill=tk.BOTH)
        scrollbar = Scrollbar(frame3, orient="vertical")
        scrollbar.config(command=self.tree1.yview)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        self.tree1.config(yscrollcommand=scrollbar.set)
        scrollbar = Scrollbar(frame4, orient="vertical")
        scrollbar.config(command=self.tree2.yview)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        self.tree2.config(yscrollcommand=scrollbar.set)
        self.tree1.pack(side=tk.BOTTOM)
        self.tree2.pack(side=tk.BOTTOM)
        frame.pack(side=tk.LEFT)
        frame2.pack(side=tk.RIGHT)

    def update_table(self, event=None):
        '''
        Call the self.func to update the table.
        :param event: None
        :return: None
        '''
        self.func(None, self.tree1.get(0, END))

    def move_table(self, event=None):
        '''
        Move item from one table to another.
        :param event: None
        :return: None
        '''
        for select in self.tree1.curselection():
            item_text = self.tree1.get(select)
            self.tree2.insert(END, item_text)
        for select in self.tree1.curselection()[::-1]:
            self.tree1.delete(select)

        for select in self.tree2.curselection():
            item_text = self.tree2.get(select)
            self.tree1.insert(END, item_text)
        for select in self.tree2.curselection()[::-1]:
            self.tree2.delete(select)

        self.update_table()

class TreeTable(Frame):
    '''
    treeview like with much more functionality (look like .Net treeview)
    '''
    def __init__(self, master, headers, data, name=None, text_by_item=0, resize=False, display=None, disable_header_replace=600 ,folder_by_item=None, folder_text="?/?", text_popup=True, resizeable=True, global_preference='TreeTable_CULUMNS'):
        """
        master: where to put the treetable.
        header: the columns headers.
        data: the data to put inside.
        text_by_item: the text header of every line (the index in the data in every line).
        resize: True to resize(when the table created or items added).
        display: gets a tuple of all the items to display(from the headers) and display them as default.
        disable_header_replace: sometime we want to disable header (because its slow), so we can give a number of rows or just true. [cant be disable on foldered tree]
        folder_by_item and folder_item used for create a treetable that have foldered some items.n
        folder_by_item: get the item to be the search for the folder_text in the data specific line.
        folder_text: will be the text in the item index to split the items with and go inside the folder tree.
        text_popup: True to enable popup for text when mouse in on some item.
        resizeable: True to resize the table automaticly.
        global_preference: the name for the global variable to put user preference (False/None to disable).
        """
        Frame.__init__(self, master, name=name)

        # Init Class Variables
        self.master = master
        self.resize = resize
        self.text_popup = text_popup
        self.text_by_item = text_by_item
        self.disable_header_replace = disable_header_replace
        self.row_search = ('', 0)
        self.last_seperator_time = 0
        self.swapped = False
        self.current_x = 0
        self.headers = headers
        self.data = data
        self.folder_by_item = folder_by_item
        self.folder_text = folder_text
        self.app_header = None

        # Check if the user put a limit to the header replace (default is 600).
        if disable_header_replace:
            try:
                disable_header_replace = int(disable_header_replace)
                self.disable_header_replace = len(data) > disable_header_replace
            except (TypeError, ValueError):
                self.disable_header_replace = False

        #: :class:`~ttk.Treeview` that only shows "headings" not "tree columns"
        # if the folder_by_item is not null we will go and create a treeview with tree, and seperate them (go deep when folder_text found).
        # for example (('item', 'abc', 'abcd'), ('?/?item2', 'abc', 'abcd'), ('?/?item3', 'abc', 'abcd'), ('?/??/?item4', 'abc', 'abcde'), ('item5', 'abc', 'abcdf'))
        # will create the following tree:
        # | header1 | header2 | header3 |
        # -------------------------------
        # | item1   | abc     | abcd    |
        # | -item2  | abc     | abcd    | item2 will be sub item of item 1
        # | -item3  | abc     | abcd    | item3 will be sub item of item 1 as well
        # | --item4 | abc     | abcde   | item4 will be sub item of item 3
        # | item5   | abc     | abcdf   | item5 dont have any ?/? so he will not be sub item
        if self.folder_by_item != None:
            self.tree = Treeview(self, columns=self.headers, name='tabletree')
            self.tree.heading("#0", text="{} [Total:{}]".format(self.headers[self.folder_by_item], len(data)))
            self.tree["displaycolumns"] = self.headers[:folder_by_item]+self.headers[folder_by_item+1:]
            self.visual_drag = Treeview(self, columns=self.headers, name='visual_drag', show="headings")
            self.visual_drag["displaycolumns"] = self.headers[:folder_by_item] + self.headers[folder_by_item + 1:]
        else:
            self.tree = Treeview(self, columns=self.headers, name='tabletree', show="headings")
            self.visual_drag = Treeview(self, columns=self.headers, name='visual_drag', show="headings")

        # Save the user preference for the display columns (this will override the display if its enable).
        if global_preference:
            if not globals().has_key(global_preference):
                globals()[global_preference] = {}

        self.global_preference = global_preference

        self.display = display if display else self.headers
        self.display = globals()[self.global_preference][str(self.headers)] if globals()[self.global_preference].has_key(str(self.headers)) else self.display
        self.tree["displaycolumns"] = self.display
        self.visual_drag["displaycolumns"] = self.display

        #: vertical scrollbar
        self.yscroll = Scrollbar(self, orient="vertical",
                                 command=self.tree.yview, name='table_yscroll')
        #: horizontal scrollbar
        self.xscroll = Scrollbar(self, orient="horizontal",
                                 command=self.tree.xview, name='table_xscroll')
        self.tree['yscrollcommand'] = self.yscroll.set  # bind to scrollbars
        self.tree['xscrollcommand'] = self.xscroll.set

        # position widgets and set resize behavior.
        self.tree.grid(column=0, row=0, sticky=(N + E + W + S))
        self.yscroll.grid(column=1, row=0, sticky=(N + S))
        self.xscroll.grid(column=0, row=1, sticky=(E + W))
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Insert all the items and init the title row callbacks (for filtering).
        self._init_title_row_callback()
        self._init_insert_items()
        if len(self.tree.get_children()) > 0:
            self.tree.focus(self.tree.get_children()[0])

        # Set original order to the items (so ctrl+t will restore to default).
        self.original_order = self.get_all_children(self.tree)
        #self.original_order = sorted(self.original_order, key=lambda x: int(str(x[1][0] if isinstance(x[1], tuple) else x[0])[1:], 16))

        # Menu creation.
        self.aMenu = Menu(master, tearoff=0)
        self.HeaderMenu = Menu(master, tearoff=0)
        self.HeaderMenu.add_command(label='Select Columns...', command=self.header_selected)
        self.HeaderMenu.add_command(label='Default Columns', command=self.display_only)
        self.HeaderMenu.add_separator()
        self.HeaderMenu.add_command(label='Hide Column', command=self.hide_selected_col)
        self.HeaderMenu.add_separator()
        if has_csv:
            self.HeaderMenu.add_command(label='Export Table To Csv', command=self.export_table_csv)
            self.HeaderMenu.add_separator()
        if resizeable:
            self.HeaderMenu.add_command(label='Resize Column', command=self.resize_selected_col)
            self.HeaderMenu.add_command(label='Resize All Columns', command=self.resize_all_columns)
        self.copy_menu = Menu(self.aMenu)

        for header in range(len(self.headers)):
            self.copy_menu.add_command(label='{}'.format(self.headers[header]), command=functools.partial(self.RunCopy, header))
        self.aMenu.add_cascade(label='Copy', menu=self.copy_menu)

        """Write Menu (may support in the future..)
        self.write_menu = Menu(self.aMenu)
        for header in range(len(self.headers)):
            self.write_menu.add_command(label='{}'.format(self.headers[header]), command=functools.partial(self.RunWrite, header))
        self.aMenu.add_cascade(label='Write', menu=self.write_menu)
        """

        # Binding keys.
        self.tree.bind('<KeyPress>', self.allKeyboardEvent if self.folder_by_item is None else self.allKeyboardEventTree)
        self.tree.bind("<Double-1>", self.OnDoubleClick)
        self.tree.bind(right_click_event, self.popup)
        self.tree.bind('<Control-c>', self.header_selected)
        self.tree.bind('<Control-C>', self.header_selected)
        self.tree.bind('<Control-t>', self.show_original_order)
        self.tree.bind('<Control-T>', self.show_original_order)

        # header press and release (if disable header replace is disable we still enable them but without the animation).
        self.tree.bind("<ButtonPress-1>", self.bDown)
        self.tree.bind("<ButtonRelease-1>", self.bUp)
        self.tree.bind('<Motion>', self.OnMotion)

        # This binding relevent only if there is virtual drag
        if not self.disable_header_replace:
            self.tree.bind("<<TreeviewOpen>>", self.open_virtual_tree)
            self.tree.bind("<<TreeviewClose>>", self.close_virtual_tree)
            self.tree.bind("<<TreeviewSelect>>", self.set_item)

    def _init_insert_items(self):
        '''
        This function insert item to the table (wheter is a regular table or a treetable).
        :return: None
        '''

        # check if this is folder tree (To make if faster there is big if on the top instead of inside, what makes this kind of duplicated code)
        if self.folder_by_item !=None:

            # Parent dics for the tree
            self.parents_dict = {}

            # the iteretion with resize
            if self.resize:

                # If the user want the header replace drag and drop support.
                if not self.disable_header_replace:

                    self.v_parents_dict = {}

                    # Go all over the data.
                    for item in self.data:
                        item = [str(c_item).replace('{', r'\{').decode('utf-8',errors='ignore') for c_item in item]
                        c_tag = re.sub('[^\S0-9a-zA-Z]', '_', item[self.text_by_item])
                        foldered = item[self.folder_by_item].count(self.folder_text)
                        item[self.folder_by_item] = item[self.folder_by_item].replace(self.folder_text, "")

                        # If this item sun of no one.
                        if not foldered or not self.parents_dict.has_key(foldered-1):
                            self.parents_dict[foldered] = self.tree.insert('', END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)
                            self.v_parents_dict[foldered] = self.visual_drag.insert('', END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)
                        else:
                            self.parents_dict[foldered] = self.tree.insert(self.parents_dict[foldered-1], END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)
                            self.v_parents_dict[foldered] = self.visual_drag.insert(self.v_parents_dict[foldered - 1], END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)

                        # adjust column's width if necessary to fit each value
                        for idx, val in enumerate(item):
                            col_width = tkFont.Font().measure(val)
                            # option can be specified at least 3 ways: as (a) width=None,
                            # (b) option='width' or (c) 'width', where 'width' can be any
                            # valid column option.
                            if self.tree.column(self.headers[idx], 'width') < col_width:
                                self.tree.column(self.headers[idx], width=col_width)
                                self.visual_drag.column(self.headers[idx], width=col_width)
                else:
                    # Go all over the data.
                    for item in self.data:
                        item = [str(c_item).replace('{', r'\{').replace('}', r'\}').decode('utf-8',errors='ignore') for c_item in item]
                        c_tag = re.sub('[^\S0-9a-zA-Z]', '_', item[self.text_by_item])
                        foldered = item[self.folder_by_item].count(self.folder_text)
                        item[self.folder_by_item] = item[self.folder_by_item].replace(self.folder_text, "")

                        # If this item sun of no one.
                        if not foldered or not self.parents_dict.has_key(foldered-1):
                            self.parents_dict[foldered] = self.tree.insert('', END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)
                        else:
                            self.parents_dict[foldered] = self.tree.insert(self.parents_dict[foldered - 1], END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)

                        # adjust column's width if necessary to fit each value
                        for idx, val in enumerate(item):
                            col_width = tkFont.Font().measure(val)
                            # option can be specified at least 3 ways: as (a) width=None,
                            # (b) option='width' or (c) 'width', where 'width' can be any
                            # valid column option.
                            if self.tree.column(self.headers[idx], 'width') < col_width:
                                self.tree.column(self.headers[idx], width=col_width)

            # No resize.
            else:

                # If the user want the header replace drag and drop support.
                if not self.disable_header_replace:

                    self.v_parents_dict = {}

                    # Go all over the data and insert the items.
                    for item in self.data:
                        item = [str(c_item).replace('{', r'\{').decode('utf-8',errors='ignore') for c_item in item]
                        c_tag = re.sub('[^\S0-9a-zA-Z]', '_', item[self.text_by_item])
                        foldered = item[self.folder_by_item].count(self.folder_text)
                        item[self.folder_by_item] = item[self.folder_by_item].replace(self.folder_text, "")

                        # If this item sun of no one.
                        if not foldered:
                            self.parents_dict[foldered] = self.tree.insert('', END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)
                            self.v_parents_dict[foldered] = self.visual_drag.insert('', END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)
                        elif self.parents_dict.has_key(foldered-1):
                            self.parents_dict[foldered] = self.tree.insert(self.parents_dict[foldered-1], END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)
                            self.v_parents_dict[foldered] = self.visual_drag.insert(self.v_parents_dict[foldered - 1], END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)
                else:

                    # Go all over the data and insert the item.s
                    for item in self.data:
                        item = [str(c_item).replace('{', r'\{').replace('}', r'\}').decode('utf-8',errors='ignore') for c_item in item]
                        c_tag = re.sub('[^\S0-9a-zA-Z]', '_', item[self.text_by_item])
                        foldered = item[self.folder_by_item].count(self.folder_text)
                        item[self.folder_by_item] = item[self.folder_by_item].replace(self.folder_text, "")

                        # If this item sun of no one.
                        if not foldered:
                            self.parents_dict[foldered] = self.tree.insert('', END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)
                        elif self.parents_dict.has_key(foldered - 1):
                            self.parents_dict[foldered] = self.tree.insert(self.parents_dict[foldered - 1], END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)

        # No headers table.
        else:
            self.insert_items(self.data)

    def _init_title_row_callback(self):
        # build tree
        for col in self.headers:
            # NOTE: Use col as column identifiers, crafty!
            # NOTE: Also change col to title case using str.title()
            # NOTE: make lambda behave nicely in a loop using default arg!
            callback = lambda c=col: self.sortby(c, False)
            self.tree.heading(col, text=col.title(), command=callback)
            self.visual_drag.heading(col, text=col.title())#, command=callback)
            # adjust the column's width to the header string
            self.tree.column(col, width=tkFont.Font().measure(col.title()))
            self.visual_drag.column(col, width=tkFont.Font().measure(col.title()))

    def insert_items(self, data):
        '''
        This function insert the data to the table
        wrap insert with try except to speedup preformance.
        :param data: list of tuples (the items to insert)
        :return: None
        '''
        # If resize is enable
        if self.resize:

            # Create with visual_drag (for drag and drop support on headers).
            if not self.disable_header_replace:
                # Go all over the data and insert the items
                for item in data:

                    # Add try except to improve performance
                    try:
                        c_tag = str(item[self.text_by_item])
                        self.tree.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                        self.visual_drag.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                    except (Exception, tk.TclError):

                        # This will fail as well (so both table will be in the same item count)
                        try:
                            self.visual_drag.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                        except (Exception, tk.TclError) as ex:
                            pass

                        try:
                            item = [str(c_item).replace('{', r'\{').replace('}', r'\}').decode('utf-8',errors='ignore') for c_item in item]
                            c_tag = re.sub('[^\S0-9a-zA-Z]', '_', str(item[self.text_by_item]))
                            self.tree.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                            self.visual_drag.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                        except tk.TclError:
                            print '[-] Fail to insert {} to the table'.format(item)
                            try:
                                self.visual_drag.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                            except tk.TclError:
                                pass

                    # adjust column's width if necessary to fit each value
                    for idx, val in enumerate(item):
                        col_width = tkFont.Font().measure(val)
                        # option can be specified at least 3 ways: as (a) width=None,
                        # (b) option='width' or (c) 'width', where 'width' can be any
                        # valid column option.
                        if self.tree.column(self.headers[idx], 'width') < col_width:
                            self.tree.column(self.headers[idx], width=col_width)
                            self.visual_drag.column(self.headers[idx], width=col_width)

            # there is no visual_drag
            else:
                # Go all over the data and insert the items
                for item in data:

                    # Add try except to improve performance
                    try:
                        c_tag = str(item[self.text_by_item])
                        self.tree.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                    except (Exception, tk.TclError):

                        try:
                            item = [str(c_item).replace('{', r'\{').replace('}', r'\}').decode('utf-8',errors='ignore') for c_item in item]
                            c_tag = re.sub('[^\S0-9a-zA-Z{}]', '_', str(item[self.text_by_item]))
                            self.tree.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                        except tk.TclError:
                            print '[-] Fail to insert {} to the table'.format(item)

                    # adjust column's width if necessary to fit each value
                    for idx, val in enumerate(item):
                        col_width = tkFont.Font().measure(val)
                        # option can be specified at least 3 ways: as (a) width=None,
                        # (b) option='width' or (c) 'width', where 'width' can be any
                        # valid column option.
                        if self.tree.column(self.headers[idx], 'width') < col_width:
                            self.tree.column(self.headers[idx], width=col_width)

        # If resize is disable.
        else:

            # Create with visual_drag (for drag and drop support on headers).
            if not self.disable_header_replace:

                # Go all over the data and insert the items
                for item in data:

                    # Add try except to improve performance
                    try:
                        c_tag = str(item[self.text_by_item])
                        self.tree.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                        self.visual_drag.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                    except (Exception, tk.TclError):

                        # This will fail as well (so both table will be in the same item count)
                        try:
                            self.visual_drag.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                        except (Exception, tk.TclError) as ex:
                            pass

                        try:
                            item = [str(c_item).replace('{', r'\{').replace('}', r'\}').decode('utf-8',errors='ignore') for c_item in item]
                            c_tag = re.sub('[^\S0-9a-zA-Z]', '_', str(item[self.text_by_item]))
                            self.tree.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                            self.visual_drag.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                        except tk.TclError:
                            print '[-] Fail to insert {} to the table'.format(item)
                            try:
                                self.visual_drag.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                            except tk.TclError:
                                pass
            else:

                # Go all over the data and insert the items
                for item in data:

                    # Add try except to improve performance
                    try:
                        c_tag = str(item[self.text_by_item])
                        self.tree.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                    except (Exception, tk.TclError):
                        try:
                            item = [str(c_item).replace('{', r'\{').replace('}', r'\}').decode('utf-8',errors='ignore') for c_item in item]
                            c_tag = re.sub('[^\S0-9a-zA-Z{}]', '_', str(item[self.text_by_item]))
                            self.tree.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                        except tk.TclError:
                            print '[-] Fail to insert {} to the table'.format(item)

        if len(self.tree.get_children()) > 0:
            self.tree.focus(self.tree.get_children()[0])

        # Set original order to the items (so ctrl+t will restore to default).
        self.original_order = self.get_all_children(self.tree)

    def get_all_children(self, tree, item="", only_opened=True):
        '''
        This function will return a list of all the children.
        :param tree: tree to iterate.
        :param item: from item
        :param only_opened: go only over the items that nop colaps.
        :return: list of all the items [(item, parent), (item, parent)]
        '''
        open_opt = tk.BooleanVar()
        children = []

        # Go all over the childrens
        for child in tree.get_children(item):

            # Append children and parent
            children.append((child, item))
            open_opt.set(str(tree.item(child, option='open')))

            # If only opened items is searched
            if open_opt.get() or not only_opened:
                children += self.get_all_children(tree, child, only_opened)
        return children

    def allKeyboardEvent(self, event):
        '''
        This function go to the item that start with the key pressed by the user (or word), this function search for the current first columns
        if column is moved its will update to the new first column.
        :param event: event
        :return: None
        '''

        # Check for valid key
        if event.keysym_num > 0 and event.keysym_num < 60000:

            # Check if there is any item selected (else select the first one).
            if len(self.tree.selection()) > 0:
                item = self.tree.selection()[0]
            else:
                item = self.tree.get_children('')[0]
            clicked_item = item

            # A timer (for types a words and not just a char.
            if time.time() - self.row_search[1] > 2:
                self.row_search = ('', self.row_search[1])

            # Check for the same character twice in a row.
            if len(self.row_search[0]) == 1 and self.row_search[0][0] == event.char.lower():
                self.row_search = (self.row_search[0][0], time.time())
            else:
                self.row_search = ('{}{}'.format(self.row_search[0], event.char.lower()), self.row_search[1])
            after_selected = False

            # Check all the rows after the current selection.
            for ht_row in self.tree.get_children():
                if clicked_item == ht_row:
                    after_selected = True
                    if time.time() - self.row_search[1] > 2 or len(self.row_search[0]) == 1:
                        continue
                if not after_selected:
                    continue
                if (self.tree["displaycolumns"][0] != '#all' and str(self.tree.item(ht_row)['values'][self.headers.index(self.tree["displaycolumns"][0])]).lower().startswith(self.row_search[0])) or str(self.tree.item(ht_row)['values'][self.text_by_item]).lower().startswith(self.row_search[0]):
                    self.tree.focus(ht_row)
                    self.tree.selection_set(ht_row)
                    self.tree.see(ht_row)
                    self.row_search = (self.row_search[0], time.time())
                    return

            # Check all the rows before the current selection.
            for ht_row in self.tree.get_children():
                if clicked_item == ht_row:
                    break
                if (self.tree["displaycolumns"][0] != '#all' and str(self.tree.item(ht_row)['values'][self.headers.index(self.tree["displaycolumns"][0])]).lower().startswith(self.row_search[0])) or str(self.tree.item(ht_row)['values'][self.text_by_item]).lower().startswith(self.row_search[0]):
                    self.tree.focus(ht_row)
                    self.tree.selection_set(ht_row)
                    self.tree.see(ht_row)
                    self.row_search = (self.row_search[0], time.time())
                    return

            self.bell()
            self.row_search = ('', 0)

    def allKeyboardEventTree(self, event):
        '''
        This function go to the item that start with the key pressed by the user (or word), this function search for the first only!
        :param event: event
        :return: None
        '''

        # Check for valid key
        if event.keysym_num > 0 and event.keysym_num < 60000:
            if len(self.tree.selection()) > 0:
                item = self.tree.selection()[0]
            else:
                item = self.tree.get_children('')[0]
            clicked_item = item
            if time.time() - self.row_search[1] > 2:
                self.row_search = ('', self.row_search[1])

            # Check for the same character twice in a row.
            if len(self.row_search[0]) == 1 and self.row_search[0][0] == event.char.lower():
                self.row_search = (self.row_search[0][0], time.time())
            else:
                self.row_search = ('{}{}'.format(self.row_search[0], event.char.lower()), self.row_search[1])
            after_selected = False

            childrens = self.get_all_children(self.tree)

            # Check all the rows after the current selection.
            for ht_row in childrens:
                ht_row = ht_row[0]
                if clicked_item == ht_row:
                    after_selected = True
                    if time.time() - self.row_search[1] > 2 or len(self.row_search[0]) == 1:
                        continue
                if not after_selected:
                    continue
                if str(self.tree.item(ht_row)['text']).replace(' ','').lower().startswith(self.row_search[0]):
                    self.tree.focus(ht_row)
                    self.tree.selection_set(ht_row)
                    self.tree.see(ht_row)
                    self.row_search = (self.row_search[0], time.time())
                    return

            # Check all the rows before the current selection.
            for ht_row in childrens:
                ht_row = ht_row[0]
                if clicked_item == ht_row:
                    break
                if str(self.tree.item(ht_row)['text']).replace(' ','').lower().startswith(self.row_search[0]):
                    self.tree.focus(ht_row)
                    self.tree.selection_set(ht_row)
                    self.tree.see(ht_row)
                    self.row_search = (self.row_search[0], time.time())
                    return

            self.bell()
            self.row_search = ('', 0)

    def RunCopy(self, cp):
        '''
        Copy the item selected to the clipboard.
        '''
        clip = self.tree
        row = self.tree.selection()[0]
        item = self.tree.item(row)
        clip.clipboard_clear()
        item_text = item['values'][cp]
        clip.clipboard_append(str(item_text))

    def OnMotion(self, event):
        """
        This function handle mouse motion event, on headers moves by the user (drag and drop support). and the tooltip help.
        :param event:
        :return:
        """

        # Handle Motion on dnd column.
        tv = event.widget

        # drag around label if visible
        if self.visual_drag.winfo_ismapped():
            self.swapped = True
            self.last_x = float(self.current_x)
            self.current_x = float(event.x)
            x = self.dx + event.x

            # middle of the dragged column.
            xm = int(x + self.visual_drag.column(self.col_from_id, 'width') / 2)
            self.visual_drag.place_configure(x=x)
            col = tv.identify_column(xm)

            # if the middle of the dragged column is in another column, swap them
            if col and tv.column(col, 'id') != self.col_from_id:
                self.swap(tv, self.col_from_id, col, 'right' if self.current_x - self.last_x > 0 else 'left')

        # Handle tooltip creation
        if self.text_popup:

            # Problem with tk version (just update the version).
            try:

                # Create small square with information
                _iid = self.tree.identify_row(event.y)

                # If hold on table header
                if not _iid or not self.tree.identify_column(event.x)[1:]:
                    return

                item = self.tree.item(_iid)
            except tk.TclError:
                return

            # Hide the current tooltip (if there is any).
            if hasattr(self, "toolTop"):
                self.toolTop.hidetip()

            # Create a tooltip.
            self.toolTop = TreeToolTip(self.tree, event)

            # Find the selected column
            col = int(self.tree.identify_column(event.x)[1:]) -1 if int(self.tree.identify_column(event.x)[1:]) else 0
            text_to_show = ""

            # Make sure to add to the foldered tree's the realy first column info as well so they have more information displayed in the tooltip.
            if self.folder_by_item != None:
                text_to_show = "{}: {}\n".format(self.headers[self.folder_by_item], self.tree.item(_iid)['values'][self.folder_by_item])

            # Get the selected column (acourding to the current display).
            display = self.tree["displaycolumns"]
            text_to_show += "{}: {}".format(self.headers[self.text_by_item], self.tree.item(_iid)['values'][self.text_by_item])


            # If we not on motion on text_by_item column(witch already displayed...).
            if self.headers[self.text_by_item] not in display or col != display.index(self.headers[self.text_by_item]):
                text_to_show += u"\n{}: {}".format(display[col], item['values'][self.headers.index(display[col])] if len(item['values']) > self.headers.index(display[col]) else '')
            self.toolTop.showtip(text_to_show)


            def leave(event):
                ''' hide the diplayed tooltip '''
                self.toolTop.hidetip()
            self.tree.bind('<Leave>', leave)

    def swap(self, tv, col1, col2, direction):
        '''
        This function swap 2 columns
        :param tv: treeview
        :param col1: col
        :param col2: col
        :param direction: direction
        :return: None
        '''
        dcols = list(tv["displaycolumns"])

        # When all the columsn is selected we get #all instead of tuples with the names of the row, so lets replace this.
        if dcols[0] == "#all":
            dcols = list(tv["columns"])

        # Get the columns id
        id1 = self.tree.column(col1, 'id')
        id2 = self.tree.column(col2, 'id')

        # Return if one of the columns is not valid (the header column for the folder table).
        if id1 == '' or id2 == '':
            return

        # Get the index of the ids.
        i1 = dcols.index(id1)
        i2 = dcols.index(id2)

        # Return if the columns is not valid (before the first or after the last).
        if (i1 - i2 > 0 and direction == 'right') or (i1 - i2 < 0 and direction == 'left'):
            return

        # Swap.
        dcols[i1] = id2
        dcols[i2] = id1

        # Display in the new order.
        tv["displaycolumns"] = dcols
        self.swapped = True

    def bDown(self, event):
        '''
        This function handle button down event (when we try replace 2 columns).
        :param event:
        :return:
        '''
        tv = tree = event.widget
        left_column = tree.identify_column(event.x)

        # Check if this columns is valid (not the header for folder).
        if left_column[1:] == '':
            return

        right_column = '#%i' % (int(tree.identify_column(event.x)[1:]) + 1)

        # Get the left index
        if (not isinstance(left_column, int)) and (not left_column.isdigit()) and (
                left_column.startswith('I') or left_column.startswith('#')):
            left_column = int(left_column[1:])
        left_column -= 1

        # This is the text header of the treeview(the left column if text header present).
        if left_column != -1:
            left_column = self.headers.index(self.tree["displaycolumns"][left_column])
            width_l = tree.column(left_column, 'width')
            self.visual_drag.column(left_column, width=width_l)

        # Get the right column
        if (not isinstance(right_column, int)) and (not right_column.isdigit()) and (
                right_column.startswith('I') or right_column.startswith('#')):
            right_column = int(right_column[1:])
        right_column -= 1

        # This is the text header of the treeview(the left column if text header present).
        if right_column < len(self.tree["displaycolumns"]):
            right_column = self.headers.index(self.tree["displaycolumns"][right_column])
            width_r = tree.column(right_column, 'width')
            self.visual_drag.column(right_column, width=width_r)

        # Problem with tk version minumum support 8.5.
        try:
            c_region = tv.identify_region(event.x, event.y)
        except tk.TclError:
            c_region = 'heading' if event.y < 26 else 'not good tk version'

        # Check the user select the header of the table.
        if c_region == 'heading':
            self.swapped = False
            col = tv.identify_column(event.x)
            self.col_from_id = tv.column(col, 'id')

            # Iterate all the treeview only if we have not disable header replace.


            # get column x coordinate and width
            if self.col_from_id and self.col_from_id != 0:
                all_children = tv.get_children() #self.get_all_children(tv)
                for i in all_children:
                    bbox = tv.bbox(i, self.col_from_id) #bbox = tv.bbox(i[1][0] if isinstance(i[1], tuple) else i[0], self.col_from_id)
                    if bbox:
                        self.dx = bbox[0] - event.x  # distance between cursor and column left border
                        #        tv.heading(col_from_id, text='')
                        def set_y(*args):
                            self.visual_drag.yview_moveto(self.yscroll.get()[0])

                        def set_y2(event):
                            shift = (event.state & 0x1) != 0
                            scroll = -1 if event.delta > 0 else 1
                            if shift:
                                self.visual_drag.xview_scroll(scroll, "units")
                            else:
                                self.visual_drag.yview_scroll(scroll, "units")

                        # Check if we display beautiful header or not
                        if not self.disable_header_replace:
                            self.visual_drag.configure(displaycolumns=[self.col_from_id], yscrollcommand=set_y)
                            self.tree.bind("<MouseWheel>", set_y2)
                            self.visual_drag.place(in_=tv, x=bbox[0], y=0, anchor='nw', width=bbox[2], relheight=1)
                            self.visual_drag.selection_set(tv.selection())
                            self.visual_drag.yview_moveto(self.yscroll.get()[0])
                        else:
                            self.visual_drag.configure(displaycolumns=[self.col_from_id])
                            self.visual_drag.place(in_=tv, x=event.x, y=0, anchor='nw', width=bbox[2], relheight=1)
                        return

        else:
            self.col_from_id = None

            # Reset the timer (if we select seperator).
            if c_region == 'separator':
                self.last_seperator_time = time.time()

    def bUp(self, event):
        ''' This function hide the visual drage when the courser is up'''
        self.visual_drag.place_forget()

    def open_virtual_tree(self, event):
        ''' This function open the visual_drag when the regulare tree is open'''
        if len(self.tree.selection()) > 0:
            self.visual_drag.item(self.tree.selection()[0], open=1)

    def close_virtual_tree(self, event):
        ''' This function close the visual_drag when the regulare tree is close'''
        if len(self.tree.selection()) > 0:
            self.visual_drag.item(self.tree.selection()[0], open=0)

    def set_item(self, event):
        ''' This function set the selection item in te visual_drag when the regulare tree is selection is change'''
        if len(self.tree.selection()) > 0:
            item = self.tree.selection()[0]
            self.visual_drag.selection_set(item)
            self.tree.focus(item)
            self.tree.see(item)

    def OnDoubleClick(self, event):
        ''' This function handle double click press (for header resize)'''
        # Double click on table header to resize
        if event and event.y < 25 and event.y > 0:
            try:
                if self.tree.identify_region(event.x, event.y) == 'separator':
                    self.resize_col(self.tree.identify_column(event.x))
            except tk.TclError:
                pass # This Tkinter version dont support identify region event.

    def resize_col(self, col):
        '''
        This function resize some collumn.
        :param col: the col to resize (fix size).
        :return: None
        '''
        if (not isinstance(col, int)) and (not col.isdigit()) and (col.startswith('I') or col.startswith('#')):
            col = int(col[1:])
        col -= 1#col-1 if col!=0 else 0

        # This is the text header of the treeview(the left column if text header present).
        if col == -1:
            return
        col = self.headers.index(self.tree["displaycolumns"][col])
        max_len = 0

        # Get the beggest line and resize
        for row in self.get_all_children(self.tree):
            row = row[0]
            item = self.tree.item(row)
            current_len = tkFont.Font().measure(str(item['values'][col]))
            if current_len > max_len:
                max_len = current_len
        self.tree.column(self.headers[col], width=(max_len))

        if not self.disable_header_replace:
            self.visual_drag.column(self.headers[col], width=(max_len))

    def display_only(self, event=None, display=None):
        ''' This function display only the wanted items (and save them)'''
        self.tree["displaycolumns"] = display if display else self.display

        if not self.disable_header_replace:
            self.visual_drag["displaycolumns"] = display if display else self.display

        if self.global_preference and display:
            globals()[self.global_preference][str(self.headers)] = display

    def header_selected(self,event=None):
        ''' This function display the move list for header selected '''

        def on_exit():
            ''' Delete the header app when he die and set to None'''
            self.app_header.destroy()
            self.app_header = None

        # If the user select to display the select columns just pop it up (if its exist, else create it).
        if self.app_header:
            self.app_header.attributes('-topmost', 1)
            self.app_header.attributes('-topmost', 0)
        else:

            # Get the current displayed columns.
            display = self.tree["displaycolumns"]

            # Get the current hiden columns
            hide = [item for item in self.headers if item not in self.tree["displaycolumns"]]

            # Remove the first header if this a folder treeview (unsupported).
            if self.folder_by_item != None:
                hide.remove(self.headers[self.folder_by_item])

            # Create the movelists gui.
            self.app_header = MoveLists(display, hide, self.display_only)
            x = self.winfo_x()
            y = self.winfo_y()
            self.app_header.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
            self.app_header.resizable(False, False)
            self.app_header.title("Select Columns")
            self.app_header.protocol("WM_DELETE_WINDOW", on_exit)

    def hide_selected_col(self):
        ''' This functio handle the hide column header menu function'''
        display = list(self.tree["displaycolumns"])
        col = self.tree.identify_column(self.HeaderMenu.c_event.x)
        if (not isinstance(col, int)) and (not col.isdigit()) and (col.startswith('I') or col.startswith('#')):
            col = int(col[1:])
        col -= 1

        # This is the text header of the treeview(the left column if text header present).
        if col == -1:
            return
        col = self.tree["displaycolumns"][col]

        display.remove(col)
        self.display_only(None, display)

    def resize_selected_col(self):
        ''' This function handle the resize column from the menu of the table header '''
        self.resize_col(self.tree.identify_column(self.HeaderMenu.c_event.x))

    def resize_all_columns(self):
        ''' This funtion resize all the columns (handle the resize all columns from the menu funciton).'''
        for col in range(len(self.tree["displaycolumns"])+1):
            self.resize_col(col)

    def SetColorItem(self, color, item=None, tag=None):
        '''
        This function set a color to a specific item/tag.
        :param color: the new color.
        :param item: item name (optional)
        :param tag: tag name (optional)
        :return: None
        '''

        # Validate that the user give item/tag and set his color.
        if item or tag:
            tag = tag if tag else self.tree.item(item)['values'][self.text_by_item]
            tag = str(tag).replace(' ', '_')
            self.tree.tag_configure(tag, background=color)
            if not self.disable_header_replace:
                self.visual_drag.tag_configure(tag, background=color)

    def export_table_csv(self):
        ''' Export the table to csv file '''
        selected = tkFileDialog.asksaveasfilename(parent=self)
        if selected and selected != '':
            with open(selected, 'w') as fhandle:
                csv_writer = csv.writer(fhandle)
                csv_writer.writerow(self.headers)

                # Export acording to if folder or not
                if self.folder_by_item != None:
                    for row in self.data:
                        csv_writer.writerow(row[:self.folder_by_item] + [row[self.folder_by_item].replace(self.folder_text, '~')] + row[self.folder_by_item+1:])
                else:
                    for row in self.data:
                        csv_writer.writerow(row)

    def popup(self, event):
        ''' This function popup the right menu '''

        # Stop swapping if the user moving some header.
        if self.swapped:
            self.bUp(event)

        # If header selected:
        if event.y < 25 and event.y > 0:
            self.HeaderMenu.c_event = event
            self.HeaderMenu.tk_popup(event.x_root, event.y_root)
        else:

            # Select the item and popup menu
            self.tree.selection_set(self.tree.identify_row(event.y))
            if not self.disable_header_replace:
                self.visual_drag.selection_set(self.tree.identify_row(event.y))
            self.aMenu.tk_popup(event.x_root, event.y_root)

    def sortby(self, col, descending):
        '''
        This function sort column
        :param col: column to sort
        :param descending: order True-descending or false-ascending (saved and switch each time)
        :return:
        '''


        # grab values to sort
        if time.time() - self.last_seperator_time < 0.75 or self.swapped:
            self.swapped = False
            return
        data = [(self.tree.set(child[0], col), child)
                for child in self.get_all_children(self.tree)]

        # now sort the data in place (try first to sort by hex value (int is good to) than by string)
        try:
            data = sorted(data, reverse=descending, key=lambda x: int(x[0], 16))
        except (ValueError, TypeError):
            data.sort(reverse=descending)

        for idx, item in enumerate(data):
            self.tree.move(item[1][0], '', idx)
            if not self.disable_header_replace:
                self.visual_drag.move(item[1][0], '', idx)

        # switch the heading so it will sort in the opposite direction
        callback = lambda: self.sortby(col, not descending)
        self.tree.heading(col, command=callback)

    def show_original_order(self, event=None):
        ''' This function show the original order of the tree (created order)'''
        for idx, item in enumerate(self.original_order):
            if isinstance(item[1], tuple):
                item = item[1]
            self.tree.move(item[0], item[1], idx)
            self.visual_drag.move(item[0], item[1], idx)

class TreeLable(TreeTable):
    '''
    Tree View with description on click
    '''

    def __init__(self, master, headers, data, name=None, text_by_item=0, resize=False, display=None, *args, **kwargs):
        TreeTable.__init__(self, master, headers, data, name, text_by_item, resize, display)
        self.tree['height'] = self.tree['height'] = 10 if len(data) > 10 else len(data)
        self.pack(expand=YES, fill=BOTH)

        # Class variables
        self.opts = {}
        self.frame = frame = ttk.Frame(master)
        self.frames = []

        counter = 0
        col_size = 4

        # Go all over the headers
        for item in headers:
            if counter % col_size == 0:
                papa = ttk.Frame(frame)
                self.frames.append((ttk.Frame(papa), ttk.Frame(papa), papa))

            # Create a label to each header.
            ttk.Label(self.frames[counter/col_size][0], text='{} : '.format(item), wraplength=500).pack(anchor='w', padx=10)
            self.opts[item] = StringVar()
            self.opts[item].set('-')
            ttk.Label(self.frames[counter/col_size][1], textvariable=self.opts[item]).pack(anchor='w')

        # Pack all the frames
        for c_frame in self.frames:
            c_frame[0].pack(side=LEFT)
            c_frame[1].pack(side=LEFT)
            c_frame[2].grid(row=self.frames.index(c_frame), column=1)
        frame.pack(anchor='nw')

        # Bind item selection change
        self.tree.bind("<<TreeviewSelect>>", self.update_items, add='+')

    def update_items(self, event=None):
        '''
        This function update the item in the label accourding to the pressed item in the treetable
        :param event: None
        :return: None
        '''

        # Return if there is not item selected
        if len(self.tree.selection()) == 0:
            return

        # Get the selected item
        item = self.tree.selection()[0]
        values = self.tree.item(item)['values']

        # Set all the items to the selected item
        for item in range(len(self.headers)):
            self.opts[self.headers[item]].set(values[item])

class TreeTree(Frame):
    '''
    Tree View with description on click (As another TreeView)
    '''

    def __init__(self, master, headers, data, name=None, text_by_item=0, resize=False, display=None, *args, **kwargs):
        Frame.__init__(self, master, name=name)
        self.master = master
        self.pw = PanedWindow(self, orient='vertical')

        # Create the main table of all the information.
        self.main_t = main_t = TreeTable(self.pw, headers,  data, name, text_by_item, resize, display, *args, **kwargs)
        self.aMenu = self.main_t.aMenu
        main_t.tree['height'] = main_t.tree['height'] = 10 if len(data) > 10 else len(data)
        main_t.pack(expand=YES, fill=BOTH)

        self.opts = {}

        # Create the lower table.
        self.mem_view = mem_view = TreeTable(self.pw, ("Members", "Values"), [], name, 0, resize, ("Members", "Values"), *args, **kwargs)
        mem_view.tree['height'] = 10 if len(headers) > 10 else len(headers)
        for item in headers:
            self.opts[item] = ''
            mem_view.tree.insert('', END, values=(item, self.opts[item]), text=item)
            mem_view.visual_drag.insert('', END, values=(item, self.opts[item]), text=item)
        mem_view.pack(expand=YES, fill=BOTH)
        self.pw.add(main_t)
        self.pw.add(mem_view)
        self.pw.pack(expand=YES, side=TOP, fill=BOTH)

        # Bind item selection change
        main_t.tree.bind("<<TreeviewSelect>>", self.update_items, add='+')

    def update_items(self, event=None):
        '''
        This function update the item in the tree accourding to the pressed item in the treetable
        :param event: None
        :return: None
        '''

        # Return if there is not item selected
        if len(self.main_t.tree.selection()) == 0:
            return

        # Get the selected item.
        item = self.main_t.tree.selection()[0]
        values = self.main_t.tree.item(item)['values']

        # Go all over the headers
        for item in range(len(self.main_t.headers)):
            self.opts[self.main_t.headers[item]] = values[item]
            index = 0

            # Set the table to the selected item.
            children_items = list(self.mem_view.tree.get_children())
            for c_item in children_items:
                self.mem_view.tree.set(c_item, "#2", self.opts[self.main_t.headers[index]])
                self.mem_view.visual_drag.set(c_item, "#2", self.opts[self.main_t.headers[index]])
                index += 1

class ObjectProperties(Frame):
    def __init__(self, master, object_info, menu_show='ObjSecurity', relate=None, *args, **kwargs):
        Frame.__init__(self, master, *args, **kwargs)
        self.title_font = tkFont.Font(family='Helvetica', size=16, weight="bold", slant="italic")
        self.relate = relate
        tabcontroller = NoteBook(self)
        self.frames = {}
        self.object_info = object_info


        # __init__ all the classes (the notebook tabs).
        for F in (ObjSecurity, ):
            page_name = F.__name__
            frame = F(parent=tabcontroller, controller=self)
            self.frames[page_name] = frame
            frame.config()
            frame.grid(row=0, column=0, sticky=E + W + N + S)
            tabcontroller.add(frame, text=page_name)

        tabcontroller.enable_traversal()
        tabcontroller.pack(fill=BOTH, expand=1)
        if self.frames.has_key(menu_show):
            tabcontroller.select(self.frames[menu_show])
        self.tabcontroller = tabcontroller

class ObjSecurity(Frame):
    '''
    This class represent the Properties Security tab.
    '''
    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        label = ttk.Label(self, text="Security", font=controller.title_font)
        label.config(anchor="center")
        label.pack(side="top", fill="x", pady=10)
        #self.pw = PanedWindow(self, orient='vertical')
        object_info = self.controller.object_info

        my_info = ''.join(('Owner, Group SIDs:\n{} ({})'.format(object_info[0][1], object_info[0][0]), '\n{} ({})'.format(object_info[1][1], object_info[1][0]), '\n'))
        lb_info = ttk.Label(self, text=my_info, wraplength=500)#, background="white")
        lb_info.pack()

        # Get the Groups security information (if we have it).
        if len(object_info[2]):
            data = object_info[2]
            dacl_treetable = TreeTree(self, headers=("ace type" ,"ace flags", "ace size", "ace sid", "ace mask"), data=data, resize=True, display=("ace sid", "ace type"))
            #dacl_treetable.tree['height'] = 7 if 7 < len(data) else len(data)
            dacl_treetable.pack(expand=YES, fill=BOTH)
            #self.pw.add(dacl_treetable)
        else:
            lb_info = ttk.Label(self, text="There Is No DACL!!!", wraplength=500)
            lb_info.pack()
            #self.pw.add(lb_info)


        # Get the Privs security information (if we have it).
        if len(object_info[3]):
            data = object_info[3]
            sacl_treetable = TreeTree(self, headers=("ace type" ,"ace flags", "ace size", "ace sid", "ace mask"), data=data, resize=True, display=("ace sid", "ace type"))
            #sacl_treetable.tree['height'] = 7 if 7 < len(data) else len(data)
            sacl_treetable.pack(expand=YES, fill=BOTH)
            #self.pw.add(sacl_treetable)

        # Pack the information.
        #self.pw.pack(fill=BOTH, expand=YES)#(side=TOP, fill=BOTH)

class DllsTable(TreeTable):
    '''
    The Tree for the dlls and devices.
    '''
    def __init__(self, master, main_table, headers, data, name=None, text_by_item=0, resize=False, display=None, pid=None):
        if not pid:
            TreeTable.__init__(self, master, headers, data, name, text_by_item, resize, display)

        # Init Class Variables
        self.pid = int(pid) if pid else pid
        self.main_selection = main_table.tree.selection()[0] if len(main_table.tree.selection()) > 0 else 'I001'
        self.send = False
        self.main_table = main_table
        self.lower_table = master
        self.last_tab = "PEImage"

        # Init Gui
        self.aMenu.add_separator()
        self.aMenu.add_command(label='Dump PE', command=self.DllDump)
        self.hexdump_menu = Menu(self.aMenu)
        self.hexdump_menu.add_command(label='ImageHexDump', command=self.ImageHex)
        self.hexdump_menu.add_command(label='MemHexDump', command=self.MemHex)
        self.properties_menu = Menu(self.aMenu)
        self.properties_menu.add_command(label='To Main Tab', command=lambda: self.Properties(None, top_level=False))
        self.properties_menu.add_command(label='Separate Tab', command=lambda: self.Properties(None))
        self.colors_menu = Menu(self.aMenu)
        self.colors_menu.add_command(label='White(Pre Check)', command=lambda: self.SetColor('white'))
        self.colors_menu.add_separator()
        self.colors_menu.add_command(label='Gray(In Progress)', command=lambda: self.SetColor('gray'))
        self.colors_menu.add_command(label='Green(Clean)', command=lambda: self.SetColor('green'))
        self.colors_menu.add_command(label='Orange(Suspicious In Check)', command=lambda: self.SetColor('orange'))
        self.colors_menu.add_command(label='Red(Suspicious, Done)', command=lambda: self.SetColor('red'))
        self.colors_menu.add_separator()
        self.colors_menu.add_command(label='Custom Color', command=lambda: self.SetColor(_from_rgb(tkColorChooser.askcolor()[0])))
        self.aMenu.add_cascade(label='HexDump', menu=self.hexdump_menu)
        self.aMenu.add_command(label='Struct Analysis', command=lambda: self.run_struct_analyze('_LDR_DATA_TABLE_ENTRY'))
        self.aMenu.add_separator()
        self.aMenu.add_cascade(label='Color', menu=self.colors_menu)
        self.aMenu.add_separator()
        self.aMenu.add_cascade(label='Properties', menu=self.properties_menu)
        self.tree.bind("<Double-1>", self.Properties)
        self.tree.bind(right_click_event, self.popup)
        self.set_saved_color()

    def DllDump(self):
        '''
        Dump a dll object from memory using dump_pe.
        :return: None
        '''
        global root
        global volself
        global lock
        if len(self.main_table.tree.selection()) == 0 or len(self.tree.selection()) == 0:
            return

        item = self.main_selection
        task = process_bases[self.pid or int(self.main_table.tree.item(item)['values'][self.main_table.text_by_item])]["proc"]
        task_space = task.get_process_address_space()
        dllitem = self.tree.selection()[0]

        # Check if we have the address of this pe.
        if not process_bases[self.pid or int(self.main_table.tree.item(item)['values'][self.main_table.text_by_item])]["dlls"].has_key(self.tree.item(dllitem)['values'][self.text_by_item]):
            def show_message_func():
                messagebox.showerror("Error", "Unable to locate this PE address in memory)", parent=self)

            queue.put((show_message_func, ()))
            return

        # Get the address and create a name for the dumped file
        module = process_bases[self.pid or int(self.main_table.tree.item(item)['values'][self.main_table.text_by_item])]["dlls"][self.tree.item(dllitem)['values'][self.text_by_item]]
        dump_file = task.ImageFileName + str(task.UniqueProcessId) + self.tree.item(dllitem)['values'][self.text_by_item] + ".dll"

        df_conf = conf.ConfObject()
        # Define conf
        df_conf.remove_option('SAVED-FILE')
        df_conf.readonly = {}
        df_conf.PROFILE = volself._config.PROFILE
        df_conf.LOCATION = volself._config.LOCATION
        df_conf.DUMP_DIR = volself._config.DUMP_DIR
        result = procdump.ProcDump(df_conf).dump_pe(task_space,
                                module,
                                dump_file)

        def show_message_func(result):
            messagebox.showinfo("DllDump done.", result, parent=self)

        queue.put((show_message_func, (result, )))

    def MemHex(self):
        '''
        Summon a thread to do hexdump (memory)
        :return: None
        '''
        if len(self.main_table.tree.selection()) == 0 or len(self.tree.selection()) == 0:
            return
        threading.Thread(target=self.PEHex_thread, args=(self.main_table.tree.item(self.main_selection), self.tree.item(self.tree.selection()[0]), True)).start()
        time.sleep(1)

    def ImageHex(self):
        '''
        Summon a thread to do hexdump (image)
        :return:
        '''
        if len(self.main_table.tree.selection()) == 0 or len(self.tree.selection()) == 0:
            return
        threading.Thread(target=self.PEHex_thread, args=(self.main_table.tree.item(self.main_selection), self.tree.item(self.tree.selection()[0]))).start()
        time.sleep(1)

    def PEHex_thread(self, mt_item, c_item, mem=False):
        '''
        HexDump a PE from the memory using dump pe mem flag accurding to the args.
        :param mt_item: the item from the main table (process)
        :param c_item: the item from the lower table (pe- dll for example)
        :param mem: flag to the dump_pe
        :return: None
        '''
        global root
        global volself

        # Get the address space.
        task = process_bases[self.pid or int(mt_item['values'][self.main_table.text_by_item])]["proc"]
        task_space = task.get_process_address_space()

        # Check if we have the address of this pe.
        if not process_bases[self.pid or int(mt_item['values'][self.main_table.text_by_item])]["dlls"].has_key(c_item['values'][self.text_by_item]):
            def show_message_func():
                messagebox.showerror("Error", "Unable to locate this PE address in memory)", parent=self)

            queue.put((show_message_func, ()))
            return
        module = process_bases[self.pid or int(mt_item['values'][self.main_table.text_by_item])]["dlls"][c_item['values'][self.text_by_item]]

        # Try to dump this pe
        try:
            dump_file = task.ImageFileName + str(task.UniqueProcessId) + c_item['values'][self.text_by_item] + ".dll"
            file_mem = dump_pe(volself, task_space,
                                module,
                                dump_file, mem)

            def create_hex_dump(dump_file, file_mem):
                app = HexDump(dump_file, file_mem, 16)
                app.title('{} ({})'.format(dump_file, 'Memory'if mem else 'File'))
                window_width = 1050
                window_height = 750
                width = app.winfo_screenwidth()
                height = app.winfo_screenheight()
                app.geometry('%dx%d+%d+%d' % (window_width, window_height, width * 0.5 - (window_width / 2), height * 0.5 - (window_height / 2)))


            queue.put((create_hex_dump, (dump_file, file_mem)))

        # Show error if the dump fail.
        except Exception as ex:
            print 'exception', ex

            def show_message_func():
                messagebox.showerror("Error", "Unable to get this PE's HexDump", parent=self)

            queue.put((show_message_func, ()))

    def Properties(self, event, top_level=True):
        '''
        Show the properties (with or without strings according to the options choose by the user).
        :param event: None
        :param top_level: as top level or insert as a tab.
        :return: None
        '''
        if event and event.y < 25 and event.y > 0:
            try:
                if self.tree.identify_region(event.x, event.y) == 'separator':
                    self.resize_col(self.tree.identify_column(event.x))
                    return
            except tk.TclError:
                return

        # Return if no item selected
        if len(self.main_table.tree.selection()) == 0 or len(self.tree.selection()) == 0:
            return

        # Display the right message (according to if the user wants to view strings or not).
        if volself._show_pe_strings == 'true':
            MessagePopUp('Data loading in the background\nThis will going to take a while because of strings searching\n(you can disable this option in the options menu)', 5, root)
        else:
            MessagePopUp('Data loading in the background\nThis can take a couple of seconds (faster than the usual because you disable the strings search)', 3, root)

        # Start the thread that do the work.
        threading.Thread(target=self.properties_thread, args=(event, self.main_table.tree.item(self.main_selection), self.tree.item(self.tree.selection()[0]), top_level)).start()
        time.sleep(1)

    def properties_thread(self, event=None, mt_item=None, c_item=None, top_level=True):
        '''
        This function summon as a thread (so the gui not freez)
        :param event: None
        :param mt_item: the item from the main table (process)
        :param c_item: the item from the lower table (pe- dll for example)
        :param top_level: Summon as a top level or as another tab.
        :return:
        '''
        global root
        global volself
        global queue

        pe_conf = conf.ConfObject()

        # Define conf
        pe_conf.remove_option('SAVED-FILE')
        pe_conf.readonly = {}
        pe_conf.PROFILE = volself._config.PROFILE
        pe_conf.LOCATION = volself._config.LOCATION
        pe_conf.KDBG = volself._config.KDBG
        pe_conf.kaddr_space = utils.load_as(pe_conf)

        # Get the address Space (from another conf so we dont have a error).
        task = obj.Object("_EPROCESS", process_bases[self.pid or int(mt_item['values'][self.main_table.text_by_item])]["proc"].obj_offset, pe_conf.kaddr_space)
        task_space = pe_conf.kaddr_space if self.pid else task.get_process_address_space()

        # Check if we have the address of this pe.
        if not process_bases[self.pid or int(mt_item['values'][self.main_table.text_by_item])]["dlls"].has_key(c_item['values'][self.text_by_item]):
            def show_message_func():
                messagebox.showerror("Error", "Unable to locate this PE address in memory)", parent=self)

            queue.put((show_message_func, ()))
            return
        module = process_bases[self.pid or int(mt_item['values'][self.main_table.text_by_item])]["dlls"][c_item['values'][self.text_by_item]]

        # Add to job queue
        module_name = c_item['values'][self.text_by_item]
        id = time.time()
        job_queue.put_alert((id, 'PE properties', "{}({}):{} Properties".format('System' if self.pid else mt_item['values'][0], self.pid or mt_item['values'][self.main_table.text_by_item], module_name), 'Running'))

        pefile = obj.Object("_IMAGE_DOS_HEADER", offset=module, vm=task_space)

        # Get nt_hreader
        try:
            nt_headers = pefile.get_nt_header()
        except Exception as ex:
            queue.put((messagebox.showerror, ("Error", "{}".format(ex), ('**kwargs', {'parent': self}))))
            return

        # Get the strings if the user wants to
        if volself._show_pe_strings == 'true':
            mem_strings_list = list(pefile.get_image(unsafe=False, memory=True, fix=False))
            mem_strings = "".join(i[1] for i in mem_strings_list)
            mem_strings = '\n'.join(get_ascii_unicode(mem_strings, False, True)[0])

            image_strings_list = list(pefile.get_image(unsafe=False, memory=False, fix=False))
            image_strings = "".join(i[1] for i in image_strings_list)
            image_strings = '\n'.join(get_ascii_unicode(image_strings, True)[0])
        else:
            mem_strings=False
            image_strings=False

        # Get dlls / modules
        lm = list(win32.modules.lsmod(pe_conf.kaddr_space)) if self.pid==4 or int(mt_item['values'][self.main_table.text_by_item])==4 else list(task.get_load_modules())
        imports = []
        exports = []

        # Get the imports.
        for c_module in lm:
            if c_module.DllBase == module:
                module_name = c_module.BaseDllName
                flags = c_module.Flags

                for mod_name, oridinal, addr, func_name in c_module.imports():
                    imports.append((str(mod_name), int(long(oridinal)), hex(long(addr)), func_name))

                for index, addr, name in c_module.exports():
                    exports.append((int(long(index)) or -1, hex(long(addr)), str(name)))
                break

        my_data = [pefile, imports, exports, mem_strings, image_strings, c_module, self.pid or int(mt_item['values'][self.main_table.text_by_item]), nt_headers]

        def change_last_tab(self, c_self):
            ''' This function remember the last tab pressed (so next time he will automatically pressed). '''
            clicked_tab = c_self.tabcontroller.tab(c_self.tabcontroller.select(), "text")
            if clicked_tab in ('PEImage', 'PEImports', 'PEExports', 'MemStrings', 'ImageStrings'):
                self.last_tab = clicked_tab

        self.change_last_tab = change_last_tab

        # Create the gui (on top level or as a tab)
        if top_level:
            def create_top_level(self):
                app = tk.Toplevel()
                PEPropertiesClass(app, my_data, self.last_tab, relate=app).pack(fill=BOTH)
                for c_child in app.winfo_children():
                    if hasattr(c_child, 'tabcontroller'):
                        c_child.tabcontroller.bind("<<NotebookTabChanged>>", lambda f: self.change_last_tab(self, c_child))
                app.title("{}({}):{} Properties".format('System' if self.pid else mt_item['values'][0], self.pid or mt_item['values'][self.main_table.text_by_item], module_name))
                app.attributes('-topmost', 1)
                app.attributes('-topmost', 0)
                x = root.winfo_x()
                y = root.winfo_y()
                app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
                window_width = 750
                window_height = 550
                width = app.winfo_screenwidth()
                height = app.winfo_screenheight()
                app.geometry('%dx%d+%d+%d' % (window_width, window_height, width * 0.5 - (window_width / 2), height * 0.5 - (window_height / 2)))

            queue.put((create_top_level, (self,)))
        else:
            def attach_to_main(self):
                c_nb = self.master.master.master or self.master
                frame = PEPropertiesClass(c_nb, my_data, self.last_tab, relate=c_nb.master)
                frame.pack(side=TOP, fill=BOTH)
                c_nb.add(frame, text="{}({}):{} Properties".format('System' if self.pid else mt_item['values'][0], self.pid or mt_item['values'][self.main_table.text_by_item], module_name))

            queue.put((attach_to_main, (self,)))

        job_queue.put_alert((id, 'PE properties', "{}({}):{} Properties".format('System' if self.pid else mt_item['values'][0], self.pid or mt_item['values'][self.main_table.text_by_item], module_name), 'Done'))

    def run_struct_analyze(self, struct_type):
        '''
        get address and sent to teal struct analyze function.
        '''
        item = self.tree.selection()[0]
        addr = self.tree.item(item)['values'][-1]
        if not addr:
            print "[-] unable to find the address of this {}".format(struct_type)
            return
        print "[+] Run Struct Analyze on {}, addr: {}".format(struct_type, addr)
        threading.Thread(target=run_struct_analyze, args=(struct_type, addr, None, int(self.pid) if self.pid else self.main_table.tree.item(self.main_selection)['values'][self.main_table.text_by_item])).start()

    def SetColor(self, color, check_comment=True):
        '''
        Set a collor to some item.
        :param color: Color
        :param check_comment: Check and alert if there is no comment.
        :return: None
        '''
        global pe_comments

        item = self.main_selection
        my_item = self.tree.selection()[0]
        tag = str(self.tree.item(my_item)['values'][self.text_by_item]).replace(' ', '_')
        self.tree.tag_configure(tag, background=color)
        self.visual_drag.tag_configure(tag, background=color)
        tag = str(self.tree.item(my_item)['values'][1 if len(self.headers) == 3 else 3]).replace(' ', '_')
        pid = int(self.pid or int(self.main_table.tree.item(item)['values'][self.main_table.text_by_item]))
        if check_comment and (pe_comments['pid'][pid][tag][1] == "Write Your Comments Here." or (pe_comments['pid'][pid][tag][1].startswith("Write Your Comments Here.") and pe_comments['pid'][pid][tag][1].endswith(")."))) and color != 'white':
            messagebox.showwarning("Undocumented PE", "RECOMMENDED:\nDouble click on the PE.\nEnter your comment", parent=self)
        pe_comments['pid'][pid][tag][1] = color

    def set_saved_color(self):
        '''
        Set the color according to the user color (this function called when the table create).
        :return: None
        '''
        global pe_comments

        item = self.main_selection
        pid = int(self.pid or int(self.main_table.tree.item(item)['values'][self.main_table.text_by_item]))

        # Go all over the table
        for child in self.get_all_children(self.tree):
            child = child[0]

            # Check if this dllstable represent a kernel modules or regular dlls.
            if len(self.headers) == 6:
                fn, description, cn, path, dll_base, ldr_addr = self.tree.item(child)['values']
            else:
                fn, path, addr, ldr_addr = self.tree.item(child)['values']

            # Skip none path
            if not path or path == '':
                continue

            # unfix the treetable
            if not pe_comments['pid'][pid].has_key(path):
                path = path.replace('\{', r'{').replace(r'\}', r'}')
                if not pe_comments['pid'][pid].has_key(path):
                    print '[-] fail color pid:{} path:{}'.format(pid, path)
                    continue

            # Collor the item.
            if pe_comments['pid'][pid][path][1] != 'white':
                item = child
                color = pe_comments['pid'][pid][path][1]
                tag = str(self.tree.item(item)['values'][self.text_by_item]).replace(' ', '_')
                self.tree.tag_configure(tag, background=color)
                self.visual_drag.tag_configure(tag, background=color)

class ProcessesTable(TreeTable):
    '''
    the tree for processes
    '''
    def __init__(self, master, headers, data, name=None, text_by_item=0, resize=False, display=None, disable_header_replace=600, folder_by_item=0, folder_text="?/?"):
        TreeTable.__init__(self, master, headers, data, name, text_by_item, resize, display, disable_header_replace, folder_by_item, folder_text)
        global tree_view_data

        # Init Class Variables
        self.lower_table = None
        self.processes_alert = []
        self.master = master
        self.frames = {}
        self.handle_or_dlls = None
        self.last_click = [0, 0]
        self.last_tab = "Image"

        # Init Class Gui
        self.tree.bind("<ButtonRelease-1>", self.OnOneClick, add='+')
        self.tree.bind("<space>", self.OnOneClick)
        #self.tree.bind("<Double-1>", self.OnDoubleClick) # Im handle it better on BottonRelease-1 (self.OnOneClick) by checking time(need this because doubleclick event failed when the time range to long-> when we update the lower pane)
        self.tree.bind("<Return>", self.OnDoubleClick)
        self.tree.bind(right_click_event, self.popup)
        self.tree.bind('<Control-h>', self.control_h)
        self.tree.bind('<Control-H>', self.control_h)
        self.tree.bind('<Control-d>', self.control_d)
        self.tree.bind('<Control-D>', self.control_d)
        self.tree.bind('<Control-N>', self.control_n)
        self.tree.bind('<Control-n>', self.control_n)
        self.tree.bind('<Control-f>', self.control_f)
        self.tree.bind('<Control-F>', self.control_f)
        self.tree.bind('<Control-u>', self.unalert_all)
        self.tree.bind('<Control-U>', self.unalert_all)
        self.hexdump_menu = Menu(self.aMenu)
        self.hexdump_menu.add_command(label='ImageHexDump', command=self.ImageHex)
        self.hexdump_menu.add_command(label='MemHexDump', command=self.MemHex)
        self.properties_menu = Menu(self.aMenu)
        self.properties_menu.add_command(label='To Main Tab', command=lambda: self.OnDoubleClick(None, top_level=False))
        self.properties_menu.add_command(label='Separate Tab', command=lambda: self.OnDoubleClick(None))
        self.colors_menu = Menu(self.aMenu)
        self.colors_menu.add_command(label='White(Pre Check)', command=lambda: self.SetColor('white'))
        self.colors_menu.add_separator()
        self.colors_menu.add_command(label='Gray(In Progress)', command=lambda: self.SetColor('gray'))
        self.colors_menu.add_command(label='Green(Clean)', command=lambda: self.SetColor('green'))
        self.colors_menu.add_command(label='Orange(Suspicious In Check)', command=lambda: self.SetColor('orange'))
        self.colors_menu.add_command(label='Red(Suspicious, Done)', command=lambda: self.SetColor('red'))
        self.colors_menu.add_separator()
        self.colors_menu.add_command(label='Custom Color', command=lambda: self.SetColor(_from_rgb(tkColorChooser.askcolor()[0])))
        self.tree.bind('<Double-1>', lambda e: 'break')
        self.plugins_menu = plugins_menu = Menu(self.aMenu, tearoff=0)
        well_known_plugins_menu = Menu(self.plugins_menu, tearoff=0)
        all_plugins_menu = Menu(self.plugins_menu, tearoff=0)
        plugins_menu.add_cascade(label="Well Known", menu=well_known_plugins_menu)
        plugins_menu.add_cascade(label="All", menu=all_plugins_menu)

        # Insert all the well known plugins to the plugin menu item.
        well_known_plugins = ["apihooks", "malfind", "threadmap", "tokenimp"]
        for plugin in range(len(well_known_plugins)):
            well_known_plugins_menu.add_command(label='{}'.format(well_known_plugins[plugin]),
                                                command=functools.partial(self.run_plugin, well_known_plugins[plugin]))

        # Insert all the plugin to the plugin menu item.
        for plugin in range(len(all_plugins[1])):
            all_plugins_menu.add_command(label='{}'.format(all_plugins[1][plugin]),
                                         command=functools.partial(self.run_plugin, all_plugins[1][plugin]))

        # Init Class Menu
        self.vt_menu = Menu(self.aMenu)
        self.vt_menu.add_command(label="Upload To VirusTotal", command=self.upload_to_virus_total)
        self.vt_menu.add_command(label="VirusTotal (Check Hash)", command=self.virus_total_summon)
        self.aMenu.add_separator()
        self.aMenu.add_command(label='ProcDump', command=self.ProcDump)
        self.aMenu.add_cascade(label='HexDump', menu=self.hexdump_menu)
        self.aMenu.add_separator()
        self.aMenu.add_cascade(label='Color', menu=self.colors_menu)
        self.aMenu.add_cascade(label='Plugins', menu=self.plugins_menu)
        self.aMenu.add_separator()
        self.aMenu.add_cascade(label="Virus Total", menu=self.vt_menu)
        self.aMenu.add_separator()
        self.aMenu.add_command(label='Vad Information', command=self.process_memory)
        self.aMenu.add_command(label='Struct Analysis', command=lambda: self.run_struct_analyze('_EPROCESS'))
        self.aMenu.add_cascade(label='Properties', menu=self.properties_menu)

        # Go all over the tree_view_data (object that contains the processes order).
        tree_view_data = [(self.tree.set(child[0], 'Process'), child)
            for child in self.get_all_children(self.tree)] if not tree_view_data else tree_view_data
        tree_view_data = sorted(tree_view_data,
                                key=lambda x: int(str(x[1][0] if isinstance(x[1], tuple) else x[0])[1:], 16))
        self.set_saved_color()

        # Create tasks list (for use by vadinfo).
        table_conf = conf.ConfObject()

        # Define conf
        table_conf.remove_option('SAVED-FILE')
        table_conf.readonly = {}
        table_conf.PROFILE = volself._config.PROFILE
        table_conf.LOCATION = volself._config.LOCATION
        table_conf.KDBG = volself._config.KDBG
        self.table_conf = table_conf
        self.kaddr_space = utils.load_as(self.table_conf)
        self.task_list = list(tasks.pslist(self.kaddr_space))
        self.lock = threading.Lock()

    def upload_to_virus_total(self):
        '''
        This Function upload an image of a process to virus total (in a thread).
        :return: None
        '''
        item = main_table.tree.selection()[0]
        values = self.tree.item(item)['values']
        threading.Thread(target=self.virus_total, args=(values,'upload')).start()

    def virus_total_summon(self):
        '''
        This function summon virus_total funciton as a thread (check hash, not upload).
        :return: None
        '''
        global plugins_output

        # Get arguments
        item = main_table.tree.selection()[0]
        values = self.tree.item(item)['values']
        pid = int(values[1])

        # Check if this process already checked in virus total (so display the result and exit).
        if plugins_output.has_key(int(pid)):
            for item in plugins_output[int(pid)]:
                if item[0] == 'VirusTotal':
                    if not 'Virus Total dont know this hash' in str(item[1]):
                        self.OnDoubleClick(None, 'VirusTotal')
                        return
                    print '[=] Scan again for this hash (its will seccuss to bring another result only if you upload your file)'
                    break
            if type(item) == tuple and item[0] == 'VirusTotal':
                plugins_output[int(pid)].remove(item)
        threading.Thread(target=self.virus_total, args=(values,)).start()

    def virus_total(self, values, vt_type='hash'):
        '''
        This function dump the file, and check the hash if vt_type='hash' else upload to virush total.
        :param values: information about the file.
        :param vt_type: 'hash' or 'upload' to upload the file or just check the hash of the file.
        :return: None
        '''
        global lock

        # Get address space of the process.
        file_path = values[-4]
        pid = int(values[1])
        process_name = values[0]
        task = process_bases[int(pid)]["proc"]
        task_space = task.get_process_address_space()

        # Check if we get all the parameters we need
        if task_space == None:
            result = "Error: Cannot acquire process AS"
        elif task.Peb == None:
            # we must use m() here, because any other attempt to
            # reference task.Peb will try to instantiate the _PEB
            result = "Error: PEB at {0:#x} is unavailable (possibly due to paging)".format(task.m('Peb'))
        elif task_space.vtop(task.Peb.ImageBaseAddress) == None:
            result = "Error: ImageBaseAddress at {0:#x} is unavailable (possibly due to paging)".format(
                task.Peb.ImageBaseAddress)
        else:

            # Dump the file
            dump_file = "executable." + task.ImageFileName + str(task.UniqueProcessId) + ".exe"
            result =dump_pe(volself, task_space,
                    task.Peb.ImageBaseAddress,
                    dump_file)

            # Check the hash else upload the file to virus total.
            if vt_type=='hash':
                hash = sha256(result['file']).hexdigest()
                threading.Thread(target=virus_total, args=(hash, process_name, pid, file_path, api_key)).start()
            elif vt_type=='upload':
                threading.Thread(target=upload_to_virus_total, args=(process_name, result['file'], api_key)).start()

    def run_struct_analyze(self, struct_type):
        ''' get address and sent to teal struct analyze function. '''
        item = main_table.tree.selection()[0]
        addr = self.tree.item(item)['values'][-1]
        if not addr:
            print "[-] unable to find the address of this {}".format(struct_type)
            return
        print "[+] Run Struct Analyze on {}, addr: {}".format(struct_type, addr)
        threading.Thread(target=run_struct_analyze, args=(struct_type, addr)).start()

    def set_saved_color(self):
        '''
        This is init function that set the color of each process to the user previews change (if any).
        :return: None
        '''
        global process_comments

        # Go all over the table
        for child in self.get_all_children(self.tree):
            child = child[0]
            process, pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc = self.tree.item(child)['values']

            # Change the color (if the color ever changed).
            if process_comments['pidColor'].has_key(pid):
                item = child
                color = process_comments['pidColor'][pid]
                tag = str(self.tree.item(item)['values'][self.text_by_item]).replace(' ', '_')
                self.tree.tag_configure(tag, background=color)
                self.visual_drag.tag_configure(tag, background=color)

    def run_plugin(self, plugin_name):
        '''
        This function summon the run plugin gui on specific process.
        :param plugin_name: the name of the plugin.
        :return: None
        '''

        # Get the pid
        item = main_table.tree.selection()[0]
        pid = self.tree.item(item)['values'][self.text_by_item]

        # Check if the plugin run before.
        if plugins_output.has_key(int(pid)):
            for item in plugins_output[int(pid)]:
                if item[0] == plugin_name:
                    self.OnDoubleClick(None, plugin_name)
                    return

        # Init GUI.
        app = tk.Toplevel()
        app.geometry("500x480")
        app.resizable(False, False)
        label = ttk.Label(app, text="Title:")
        label.pack()
        txt_entry = ttk.Entry(app, width=380)
        txt_entry.insert(0, plugin_name)
        txt_entry.pack()
        word_text = scrolledtext.ScrolledText(app, undo=True)
        word_text.pack()
        print '[+] run {}'.format(plugin_name)

        # Display the command line (check if memtriage or regulare volatility).
        if volself.is_memtriage:
            command = r'"{}" "{}" --plugins={} -p {}'.format(sys.executable, volself._vol_path, plugin_name, pid)
        else:
            file_path = urllib.url2pathname(volself._config.location[7:])
            profile = volself._config.PROFILE
            command = r'"{}" "{}" --plugins="{}" -f "{}" --profile={} {} -p {}'.format(sys.executable, volself._vol_path, all_plugins[0], file_path, profile, plugin_name, pid)
        word_text.insert("1.0", command)


        def run_plugin_thread():
            ''' This function summon the thread to run the plugin'''
            command = word_text.get("1.0", 'end-1c')
            tab_name = txt_entry.get()
            app.destroy()
            print '[+] run', command
            threading.Thread(target=self.run_plugin_thread, args=(command, pid, tab_name)).start()

        # Create the run button
        apply = ttk.Button(app, text="Run & Update Properties", command=run_plugin_thread)
        apply.pack()

    def run_plugin_thread(self, command, pid, tab_name):
        '''
        This function run the plugin and append the result
        :param command: command line to run
        :param pid: process pid
        :param tab_name: process name
        :return: None
        '''
        global plugins_output

        # Run the plugin
        p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p.wait()

        # Print the result
        print '[+] tab_name:', tab_name
        print output

        # Create the list of plugins (if the user never run a plugin on this process).
        if not plugins_output.has_key(int(pid)):
            plugins_output[int(pid)] = []

        # If the user run the same plugin more than once before he get the output.
        if not (tab_name, output) in plugins_output[int(pid)]:
            plugins_output[int(pid)].append((tab_name, output))

    def SetColor(self, color, check_comment=True):
        '''
        This function let the user change a color to some process
        :param color: color
        :param check_comment: if to check if the user add a comment
        :return: None
        '''
        global process_comments

        # Get the tag.
        item = main_table.tree.selection()[0]
        tag = str(self.tree.item(item)['values'][self.text_by_item]).replace(' ', '_')

        # Configure color to the tag.
        self.tree.tag_configure(tag, background=color)
        self.visual_drag.tag_configure(tag, background=color)

        # Check the comment
        if check_comment and (process_comments[int(tag)] == "Write Your Comments Here." or (process_comments[int(tag)].startswith("Write Your Comments Here.") and process_comments[int(tag)].endswith(")."))) and color != 'white':
            messagebox.showwarning("Undocumented Process", "RECOMMENDED:\nDouble click on the process.\nEnter your comment", parent=self)

        # Remember the data.
        process_comments['pidColor'][int(tag)] = color

    def ProcDump(self, event=None):
        ''' This function summon the ProcDumpThread function in a thread'''
        threading.Thread(target=self.ProcDumpThread, args=(process_bases[int(self.tree.item(self.tree.selection()[0])['values'][self.text_by_item])]["proc"], )).start()
        time.sleep(1)

    def ProcDumpThread(self, task):
        '''
        This function dump a process
        :param task: the process
        :return: None
        '''
        global queue
        global process_bases
        global volself
        global lock

        # Get the address space and check if this is a valid address space
        task_space = task.get_process_address_space()
        if task_space == None:
            result = "Error: Cannot acquire process AS"
        elif task.Peb == None:
            # we must use m() here, because any other attempt to
            # reference task.Peb will try to instantiate the _PEB
            result = "Error: PEB at {0:#x} is unavailable (possibly due to paging)".format(task.m('Peb'))
        elif task_space.vtop(task.Peb.ImageBaseAddress) == None:
            result = "Error: ImageBaseAddress at {0:#x} is unavailable (possibly due to paging)".format(task.Peb.ImageBaseAddress)
        else:
            dump_file = "executable." + task.ImageFileName + str(task.UniqueProcessId) + ".exe"
            df_conf = conf.ConfObject()
            # Define conf
            df_conf.remove_option('SAVED-FILE')
            df_conf.readonly = {}
            df_conf.PROFILE = volself._config.PROFILE
            df_conf.LOCATION = volself._config.LOCATION
            df_conf.DUMP_DIR = volself._config.DUMP_DIR
            result = procdump.ProcDump(df_conf).dump_pe(task_space,
                                task.Peb.ImageBaseAddress,
                                dump_file)
        #PopUp result
        def show_message_func(result):
            messagebox.showinfo("ProcDump done.", result, parent=self)

        queue.put((show_message_func, (result, )))

    def MemHex(self):
        ''' This function summon the ProcHexThread in a thread with the mem=True'''
        threading.Thread(target=self.ProcHexThread, args=(process_bases[int(self.tree.item(self.tree.selection()[0])['values'][self.text_by_item])]["proc"], True)).start()
        time.sleep(1)
    def ImageHex(self):
        ''' This function summon the ProcHexThread in a thread with the mem=False (default)'''
        threading.Thread(target=self.ProcHexThread, args=(process_bases[int(self.tree.item(self.tree.selection()[0])['values'][self.text_by_item])]["proc"], )).start()
        time.sleep(1)
    def ProcHexThread(self, task, mem=False):
        '''
        This fucntion dump the process image (using dump_pe), create a hexdump and display it
        :param task: process
        :param mem: flag in dump_pe
        :return: None
        '''
        global process_bases

        # Get the address space and check if this is a valid address space
        task_space = task.get_process_address_space()
        if task_space == None:
            result = "Error: Cannot acquire process AS"
            def show_message_func(result):
                messagebox.showerror("Error", result, parent=self)

            queue.put((show_message_func, (result,)))
        elif task.Peb == None:
            # we must use m() here, because any other attempt to
            # reference task.Peb will try to instantiate the _PEB
            result = "Error: PEB at {0:#x} is unavailable (possibly due to paging)".format(task.m('Peb'))
            def show_message_func(result):
                messagebox.showerror("Error", result, parent=self)

            queue.put((show_message_func, (result,)))
        elif task_space.vtop(task.Peb.ImageBaseAddress) == None:
            result = "Error: ImageBaseAddress at {0:#x} is unavailable (possibly due to paging)".format(task.Peb.ImageBaseAddress)
            def show_message_func(result):
                messagebox.showerror("Error", result, parent=self)

            queue.put((show_message_func, (result,)))
        else:

            try:

                # Give a name to the dump file and dump it.
                dump_file = "executable." + task.ImageFileName + str(task.UniqueProcessId) + ".exe"
                file_mem = dump_pe(volself,task_space,
                                task.Peb.ImageBaseAddress,
                                dump_file, mem)
                def create_hex_dump(dump_file, file_mem):
                    ''' This function display the HexDump '''
                    app = HexDump(dump_file, file_mem, 16)
                    app.title('{} ()'.format(dump_file, 'Memory' if mem else 'File'))
                    window_width = 1050
                    window_height = 750
                    width = app.winfo_screenwidth()
                    height = app.winfo_screenheight()
                    app.geometry('%dx%d+%d+%d' % (window_width, window_height, width * 0.5 - (window_width / 2), height * 0.5 - (window_height / 2)))

                queue.put((create_hex_dump, (dump_file, file_mem)))

            # Alert the user if the funciton fail
            except Exception:
                def show_message_func():
                    messagebox.showerror("Error", "Unable to get this {} HexDump".format('memory' if mem else 'file'), parent=self)

                queue.put((show_message_func, ()))

    def process_memory(self, event=None):
        '''
        Call the proccess_memory_thread as a thread
        :param event: None
        :return: None
        '''
        threading.Thread(target=self.process_memory_thread, args=(process_bases[int(self.tree.item(self.tree.selection()[0])['values'][self.text_by_item])]["proc"],)).start()
        MessagePopUp(
            'Data loading in the background\nThis will going to take a while because it\'s go all over the VAD\'s',
            3.5, root)
        time.sleep(1)
    def process_memory_thread(self, task):
        '''
        Get Vad information
        :param task: _EPROCESS
        :return: None
        '''

        id = time.time()
        job_queue.put_alert((id, 'Memory Information', 'get all the memory information - {} ({})'.format(str(task.ImageFileName), int(task.UniqueProcessId)), 'Running'))
        self.lock.acquire()

        # Get process from another conf (so we can run in thread).
        for c_task in self.task_list:
            if c_task.obj_offset == task.obj_offset:
                task = c_task
                break

        stacks = {}
        heaps = {}
        heaps_segment = {}
        task_peb = task.Peb

        # Go all over the heaps to get the addresses of the head and the segments.
        for heap in task_peb.ProcessHeaps.dereference():
            heaps[int(heap.obj_offset)] = heap.ProcessHeapsListIndex

            # Don't check on xp. (todo-> Check the version instead)
            if hasattr(heap, 'SegmentListEntry'):
                for heap_segment in list(heap.SegmentListEntry.list_of_type("_HEAP_SEGMENT", "SegmentListEntry")):
                    heaps_segment[int(heap_segment.obj_offset)] = heap.ProcessHeapsListIndex


        # This is all other memory types.
        other_memory_range = {task_peb.obj_offset: 'PEB',
                              task_peb.ReadOnlySharedMemoryBase.v(): 'Read Only Memory Base', # Shared / static server data...
                              task_peb.GdiSharedHandleTable.v(): 'Gdi Shared Handle Table',
                              task_peb.AnsiCodePageData.v(): 'Ansi Code Page Data',
                              task_peb.pShimData.v(): 'Shim Data',
                              0x7ffe0000: 'User Shared Data'
                              }

        # todo-> Check the version instead:
        if hasattr(task_peb, 'LeapSecondData'):
            other_memory_range.update({task_peb.LeapSecondData.v(): 'Leap Second Data'})

        # Go all over the threads and get stack information.
        for thread in task.ThreadListHead.list_of_type("_ETHREAD", "ThreadListEntry"):
            teb = obj.Object("_TEB", offset=thread.Tcb.Teb, vm=task.get_process_address_space())
            if teb:

                # Check terminated thread (also with exit time).
                if 'PS_CROSS_THREAD_FLAGS_TERMINATED' in str(thread.CrossThreadFlags) or int(thread.ExitTime) != 0:
                    status = 'Terminate'
                else:
                    # If thread is waiting get also the wait reason
                    if thread.Tcb.State == 5:
                        status = '{} ({})'.format(str(thread.Tcb.State), str(thread.Tcb.WaitReason))
                    else:
                        status = str(thread.Tcb.State)

                # Stack Commit memory
                stacks[teb.NtTib.StackBase.v()] = 'Stack Base (tid: {}) [{}]'.format(int(thread.Cid.UniqueThread), status)

                # From StackLimit to here is the resered memory to the stack.
                stacks[teb.DeallocationStack.v()] = 'Stack Reserved | Stack Guard start from {} (tid: {}) [{}]'.format(hex(teb.NtTib.StackLimit.v()), int(thread.Cid.UniqueThread), status)

        vad_data = []

        # Go all over the vads
        for vad in task.VadRoot.traverse():
            if vad != None:

                controlAreaAddr = 0
                segmentAddr = 0
                numberOfSectionReferences = -1
                numberOfPfnReferences = -1
                numberOfMappedViews = -1
                numberOfUserReferences = -1
                controlFlags = ""
                fileObjectAddr = 0
                use = ""
                firstPrototypePteAddr = 0
                lastContiguousPteAddr = 0
                flags2 = ""
                vadType = ""

                protection = vadinfo.PROTECT_FLAGS.get(vad.VadFlags.Protection.v(), hex(vad.VadFlags.Protection))

                # XP dont have this field.
                if hasattr(vad.VadFlags, "VadType"):
                    vadType = vadinfo.MI_VAD_TYPE.get(vad.VadFlags.VadType.v(), hex(vad.VadFlags.VadType))

                try:
                    control_area = vad.ControlArea

                    # Check that this is not private memory
                    if vad.VadFlags.PrivateMemory != 1 and control_area:
                        if control_area:
                            controlAreaAddr = control_area.dereference().obj_offset
                            segmentAddr = control_area.Segment
                            numberOfSectionReferences = control_area.NumberOfSectionReferences
                            numberOfPfnReferences = control_area.NumberOfPfnReferences
                            numberOfMappedViews = control_area.NumberOfMappedViews
                            numberOfUserReferences = control_area.NumberOfUserReferences
                            controlFlags = control_area.u.Flags
                            file_object = vad.FileObject

                            if file_object:
                                fileObjectAddr = file_object.obj_offset
                                use = file_object.file_name_with_device()

                except AttributeError:
                    pass

                # Try to find the use of this address:
                if use == '':
                    if vad.Start in other_memory_range:
                        use = other_memory_range[vad.Start]
                    elif vad.Start in stacks:
                        use = stacks[vad.Start]
                    elif vad.Start in heaps:
                        use = 'Heap (ID {})'.format(heaps[vad.Start])
                    elif vad.Start in heaps_segment:
                        use = 'Heap Segment (ID {})'.format(heaps_segment[vad.Start])

                try:
                    firstPrototypePteAddr = vad.FirstPrototypePte
                    lastContiguousPteAddr = vad.LastContiguousPte
                    flags2 = str(vad.u2.VadFlags2)
                except AttributeError:
                    pass
                vad_data.append([hex(vad.Start).replace('L', '') if isinstance(vad.Start, long) or isinstance(vad.Start, int) else str(vad.StartAddress).replace('L', ''),
                                 hex(vad.End),
                                 hex(vad.End - vad.Start).replace('L', ''),
                                 str("{} ({})".format(vad.Tag, vad.tag_map[str(vad.Tag)]) if vad.Tag else ''),
                                 str(vad.VadFlags or ''),
                                 str(protection or ''),
                                 str(vadType or ''),
                                 hex(controlAreaAddr),
                                 hex(segmentAddr),
                                 int(numberOfSectionReferences),
                                 int(numberOfPfnReferences),
                                 int(numberOfMappedViews),
                                 int(numberOfUserReferences),
                                 str(controlFlags or ''),
                                 hex(fileObjectAddr),
                                 str(use or ''),
                                 hex(firstPrototypePteAddr),
                                 hex(lastContiguousPteAddr),
                                 str(flags2 or ''),
                                 vad.v()], )

        queue.put((self.display_mem_info, (vad_data, task)))
        job_queue.put_alert((id, 'Memory Information', 'get all the memory information - {} ({})'.format(str(task.ImageFileName), int(task.UniqueProcessId)), 'Done'))
    def display_mem_info(self, data, task):
        '''
        Display the Memory information screen
        :param data:
        :return:
        '''
        app = tk.Toplevel()
        x = root.winfo_x()
        y = root.winfo_y()
        app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
        treetree = TreeTree(app, headers=(
        "Start", "End", "Size", "Tag", "Flags", "Protection", "Type", "Control Area", "Segment",
        "Number of Section References", "Number Of Pfn References", "Number Of Mapped Views",
        "Number Of User References", "Control Flags", "file Object Addr", "Use", "First Prototype Pte",
        "Last Contiguous Pte", "Flags2"), data=data, display=('Start', 'Size', "Use", "Protection", "Control Flags"))
        treetree.pack(expand=YES, fill=BOTH)
        app.geometry("750x500")
        app.title("{} ({}): Memory information (from VAD)".format(str(task.ImageFileName), int(task.UniqueProcessId)))
        self.lock.release()

        def vad_analyze(self):
            '''
            Run Struct analyzer on the vad
            :param self: the TreeTree
            :return: None
            '''

            item = self.main_t.tree.selection()[0]
            values = self.main_t.tree.item(item)['values']

            addr = values[-1]
            struct_type = values[3][values[3].find('(')+1:-1] #vad_type[values[3]]
            if not addr:
                print "[-] unable to find the address of this {}".format(struct_type)
                return
            print "[+] Run Struct Analyze on {}, addr: {}".format(struct_type, addr)
            threading.Thread(target=run_struct_analyze, args=(struct_type, addr)).start()


        treetree.main_t.vad_analyze = vad_analyze
        treetree.main_t.aMenu.add_command(label='Struct Analysis', command=lambda:treetree.main_t.vad_analyze(treetree))

    def control_d(self, event=None):
        ''' This function handle ctrl+d press '''

        # Return if there is no item selected.
        if len(self.tree.selection()) == 0:
            messagebox.showerror("Error", "Please select a process first.", parent=self)
            return

        if self.handle_or_dlls == 'Dlls':
            self.handle_or_dlls = None
            if self.lower_table:
                self.master.remove(self.lower_table)
                self.lower_table.destroy()
                self.lower_table = None
        else:
            self.handle_or_dlls = 'Dlls'
            if self.lower_table:
                self.master.remove(self.lower_table)
            self.show_lower_pane('Dlls')

    def control_h(self, event):
        ''' This function handle ctrl+h press '''

        # Return if there is no item selected.
        if len(self.tree.selection()) == 0:
            messagebox.showerror("Error", "Please select a process first.", parent=self)
            return

        if self.handle_or_dlls == 'Handles':
            self.handle_or_dlls = None
            if self.lower_table:
                self.master.remove(self.lower_table)
                self.lower_table.destroy()
                self.lower_table = None
        else:
            self.handle_or_dlls = 'Handles'
            if self.lower_table:
                self.master.remove(self.lower_table)
            self.show_lower_pane('Handles')

    def control_n(self, event):
        ''' This function handle ctrl+h press '''

        # Return if there is no item selected.
        if len(self.tree.selection()) == 0:
            messagebox.showerror("Error", "Please select a process first.", parent=self)
            return

        if self.handle_or_dlls == 'Network':
            self.handle_or_dlls = None
            if self.lower_table:
                self.master.remove(self.lower_table)
                self.lower_table.destroy()
                self.lower_table = None
        else:
            self.handle_or_dlls = 'Network'
            if self.lower_table:
                self.master.remove(self.lower_table)
            self.show_lower_pane('Network')

    def show_lower_pane(self, frame_to_show=None):
        '''
        This function summon the lower pane.
        :param frame_to_show: the last tab pressed by the user (remember).
        :return: None
        '''
        global root
        global files_info
        global process_dlls
        global process_handles
        global process_connections

        # Destroy previews table (if any)
        if not self.lower_table is None:
            self.handle_or_dlls = frame_to_show or ("Dlls", "Handles", "Network")[self.lower_table.index(self.lower_table.select())]
            self.lower_table.destroy()
        else:
            self.handle_or_dlls = frame_to_show

        self.lower_table = NoteBook(self.master)
        item = self.tree.selection()[0]
        pid = int(self.tree.item(item)['values'][self.text_by_item])
        data = process_dlls[pid]
        good_data = []

        # Get all the dlls data.
        for item in data:

            # Check if fail to get this dll data.
            if "Failed to get dll name on address: " in item:
                good_data.append((item,"","","","",""))
            else:
                cn = ""
                Description = ""
                if files_info.has_key(str(item).lower()):
                    if files_info[str(item).lower()].has_key("CompanyName"):
                        cn = files_info[str(item).lower()]["CompanyName"]
                    if files_info[str(item).lower()].has_key("FileDescription"):
                        Description = files_info[str(item).lower()]["FileDescription"]
                good_data.append((item[item.rfind('\\')+1:], cn, Description, item) + ((process_bases[pid]['dlls'][item[item.rfind('\\')+1:]], process_bases[pid]['ldr'][item[item.rfind('\\')+1:]]) if process_bases[pid]['dlls'].has_key(item[item.rfind('\\')+1:]) else (-1, -1)))

        # Create the dll data table.
        self.dlls_table = dlls_table = DllsTable(self.lower_table, self, headers=["Name", "Company Name", "Description", "Path", "Dll Base", "Ldr Address"], data=good_data, resize=False, display=("Name", "Company Name", "Description", "Path"))
        self.frames['Dlls'] = dlls_table
        dlls_table.pack(side=TOP, fill=BOTH)
        self.lower_table.add(dlls_table, text='Dlls')

        # Handles
        item = self.tree.selection()[0]
        if process_handles.has_key(int(self.tree.item(item)['values'][self.text_by_item])):

            # If options.show unnamed handles:
            if volself._show_unnamed_handles == 'true':
                data = process_handles[int(self.tree.item(item)['values'][self.text_by_item])]
            else:
                # Only named handles.
                data = []
                for val in process_handles[int(self.tree.item(item)['values'][self.text_by_item])]:
                    if val[1] != '':
                        data.append(val)
        else:
            if done_run.has_key('process_handles') and done_run['process_handles']:
                data = [('No', 'handles', 'found', '0', '0', '0', '0', '0', '0')]
            else:
                data = [('Searching', 'for', 'handles', '0', '0', '0', '0', '0', '0')]

        # Create the handles data table.
        self.handles_tablel = handles_table = TreeTable(self.lower_table, headers=("Type", "Name", "File Share Access", "Handle", "Access", "Access (meaning)", "Virtual Address", "Physical Address"), data=data, resize=False, display=("Type", "Name", "File Share Access", "Handle", "Access", "Access (meaning)"))
        self.frames['Handles'] = handles_table
        handles_table.pack(side=TOP, fill=BOTH)
        def view_security_information():
            type_to_type_name = {'Key': 'Registry',}
            not_supported_yet = ['File', 'Registry']

            proc_item = self.tree.selection()[0]
            pid = int(self.tree.item(proc_item)['values'][self.text_by_item])
            item = self.handles_tablel.tree.selection()[0]
            data = self.handles_tablel.tree.item(item)['values']
            obj_type = data[0]

            # Validate name
            if obj_type in type_to_type_name:
                obj_type = type_to_type_name[obj_type]

            # Validate that we know how to parse this type of object (from handle table)
            if obj_type in not_supported_yet:
                messagebox.showerror("Error!", "Sorry,\nThis object parsing is not supported from the handle table.", parent=self.handles_tablel)
                return

            obj_va = data[-2]
            obj_name = data[1]
            print(data)
            print(obj_type, obj_va)
            for c_task in self.task_list:
                if int(c_task.UniqueProcessId) == pid:
                    break
            addr_space = c_task.get_process_address_space()
            oh = obj.Object("_OBJECT_HEADER", obj_va - addr_space.profile.get_obj_offset('_OBJECT_HEADER', 'Body'), addr_space)#.SecurityDescriptor
            
            # Get The Data
            try:
                data = get_security_info(oh, addr_space, obj_type)
            except TypeError:
                messagebox.showerror("Error!", "Sorry,\nUnable to parse the SID object", parent=self.handles_tablel)
                return

            # Create the top level
            app = tk.Toplevel()
            x = root.winfo_x()
            y = root.winfo_y()
            app.geometry("+%d+%d" % (x + ABS_X + 200, y + ABS_Y + 30))
            ObjectProperties(app, data).pack(fill=BOTH, expand=YES)
            app.title("{} - {} :{} Properties".format(obj_type, obj_name, obj_va))
            window_width = 550
            window_height = 600
            app.geometry('%dx%d' % (window_width, window_height))



        handles_table.aMenu.add_command(label='Security Information', command=view_security_information)
        self.lower_table.add(handles_table, text='Handles')

        # Get and create the network data table.
        data = [tup for tup in process_connections[int(self.tree.item(item)['values'][self.text_by_item])]] if process_connections.has_key(int(self.tree.item(item)['values'][self.text_by_item])) else [
            ("There", "is", "no", "conenctions", "at", "all") if len(process_connections) > 0 else ["searching", "for",
                                                                                                    "connections,",
                                                                                                    "try", "again",
                                                                                                    "later"]]
        network_table = TreeTable(self.lower_table, headers=("Pid", "Protocol", "Local Address", "Remote Address", "State", "Created", "Offset"), data=data, resize=False)
        self.frames['Network'] = network_table
        network_table.pack(side=TOP, fill=BOTH)
        self.lower_table.add(network_table, text='Network')

        # Create the notebook
        self.master.add(self.lower_table)
        self.lower_table.handles_table = handles_table
        self.lower_table.dlls_table = dlls_table
        self.lower_table.network_table = network_table
        if self.handle_or_dlls:
            self.lower_table.select(self.frames[self.handle_or_dlls])

        # Resize Windows if handles dlls will not be displayed well:
        if self.master.master.master.winfo_height() < 451:
            self.master.master.master.geometry('{}x630'.format(self.master.master.master.winfo_width()))

    def OnOneClick(self, event):
        '''
        Handle one click event
        :param event: event
        :return: None
        '''

        # Not header
        if event.y > 25:
            item = self.tree.selection()[0]
            pid = self.tree.item(item)['values'][self.text_by_item]
            if pid in self.processes_alert:
                tag = str(pid)
                self.tree.item(item, tags=tag)
                self.processes_alert.remove(pid)

            if self.last_click[1] == item:

                # Check if this is double click event.
                if time.time() - self.last_click[0] < 0.9:# and self.lower_table:
                    #self.tree.item(item, open=1 - self.tree.item(item, option='open'))
                    self.OnDoubleClick(None)
                self.last_click[0] = time.time()
                self.last_click[1] = item
                return

            # Summon the right table.
            if self.handle_or_dlls == 'Dlls':
                self.show_lower_pane()
            elif self.handle_or_dlls == 'Handles':
                self.show_lower_pane()
            elif self.handle_or_dlls == 'Network':
                self.show_lower_pane()

            self.last_click[0] = time.time()
            self.last_click[1] = item

    def OnDoubleClick(self, event, menu_show='Image', select=None, top_level=True):
        '''
        This function display the properties gui
        :param event: None
        :param menu_show: previews selected tab by the user (remember)
        :param select: select specific tab.
        :param top_level: as top lovel or another tab
        :return: None
        '''
        # Double click on table header to resize
        if event and event.y < 25 and event.y > 0:
            try:
                if self.tree.identify_region(event.x, event.y) == 'separator':
                    self.resize_col(self.tree.identify_column(event.x))
                return
            except tk.TclError:
                return
        # Double click where no item selected
        elif len(self.tree.selection()) == 0:
            messagebox.showerror("Error", "Please select a process first.", parent=self)
            return

        global root
        global process_handles
        item = select or self.tree.selection()[0]
        if event:
            self.tree.item(item, open=1 - self.tree.item(item, option='open'))

        proc_name = self.tree.item(item)['values'][0]

        def change_last_tab(self, c_self):
            ''' This function remember the last user selected tab '''
            clicked_tab = c_self.tabcontroller.tab(c_self.tabcontroller.select(), "text")
            if clicked_tab in ('Image', 'Imports', 'Performance', 'Services', 'Threads', 'TcpIp', 'Security', 'Environment', 'Job'):
                self.last_tab = clicked_tab

        self.change_last_tab = change_last_tab

        # Display the process properties (as top level else as tab).
        if top_level:
            app = tk.Toplevel()
            x = root.winfo_x()
            y = root.winfo_y()
            app.geometry("+%d+%d" % (x + ABS_X + 200, y + ABS_Y + 30))
            if menu_show == "Image":
                menu_show = self.last_tab
            PropertiesClass(app, menu_show=menu_show, selection=item, relate=app).pack(fill=BOTH, expand=YES)
            for c_child in app.winfo_children():
                if hasattr(c_child, 'tabcontroller'):
                    c_child.tabcontroller.bind("<<NotebookTabChanged>>", lambda f:self.change_last_tab(self, c_child))
            app.title("{}:{} Properties".format(proc_name, self.tree.item(item)['values'][self.text_by_item]))
            window_width = 750
            window_height = 500
            app.geometry('%dx%d' % (window_width, window_height))
        else:
            frame = PropertiesClass(self.master.master, menu_show=menu_show, selection=item, relate=self.master.master.master)
            frame.pack(side=TOP, fill=BOTH)
            self.master.master.add(frame, text="{}:{} Properties".format(proc_name, self.tree.item(item)['values'][self.text_by_item]))

    def control_f(self, event=None):
        ''' This function handle ctrl+f press (summon the search) '''
        app = Search(self.lower_table, self, headers=("PROCESS", "PID", "Type", "Name"))
        app.title("Search - Handle or Dll")
        app.geometry("500x300")

    def unalert_all(self, event=None):
        ''' This function call a function that unalert all the processes '''
        queue.put((self.unalert_all_thread, ()))

    def unalert_all_thread(self):
        ''' This function unalert all the processes '''
        for i in self.get_all_children(self.tree):
            i = i[0]
            try:
                self.tree.item(i, tags=self.tree.item(i)['values'][self.text_by_item])
                self.visual_drag.item(i, tags=self.visual_drag.item(i)['values'][self.text_by_item])
            except TclError:
                pass
        self.processes_alert = []

    def set_processes_alert(self, pid_list):
        '''
        Set all the procesess from the pid list to be alerted (change colors)
        :param pid_list: list of pids
        :return:
        '''
        self.processes_alert = pid_list

        # Insert all the processes to the colored tag (called process_alerts)
        for i in self.get_all_children(self.tree):
            i = i[0]
            pid = self.tree.item(i)['values'][self.text_by_item]
            if pid in self.processes_alert:
                self.tree.item(i, tags="process_alerts")
                self.visual_drag.item(i, tags="process_alerts")
        threading.Thread(target=self.process_alert).start()

    def process_alert(self, colors=['yellow', 'white'], color_index=0):
        '''
        This process set the tag of the self.processes_alert process to another color from colors
        :param colors: the colors to change to
        :param color_index: the index in colors
        :return: None
        '''

        # Go all over the alerted processes.
        while(len(self.processes_alert)):
            color = colors[color_index]
            color_index = (color_index + 1) % len(colors)

            def set_color():
                ''' This function set the tag for a process (so the collor change as well '''
                self.tree.tag_configure('process_alerts', background=color)
                self.visual_drag.tag_configure('process_alerts', background=color)
            queue.put((set_color, ()))
            time.sleep(0.9)

    def show_process_tree(self):
        ''' This function return the table to the main state '''
        #global tree_view_data
        #for idx, item in enumerate(tree_view_data):
        #	if isinstance(item[1], tuple):
        #		item = item[1]
        #	self.tree.move(item[0], item[1], idx)
        #	self.visual_drag.move(item[0], item[1], idx)
        self.show_original_order()

class NBTab(TreeTable):
    '''
    Specific tab for the NootBook class (with functionality to display process properties and jump to main.
    '''
    def __init__(self, master, headers, data, jmp_pid_index=None, jmp_pid=None, index_pid=None, name=None, text_by_item=0, resize=False, display=None):
        TreeTable.__init__(self, master, headers, data, name, text_by_item, resize, display)

        # Init Class Variables.
        self.master = master
        self.jmp_pid_index = int(jmp_pid_index) # the index from the main_table
        self.jmp_name = jmp_pid # the name of the element (value)        <----- the user should choce on of them.
        self.index_pid = index_pid # the index where the element value is <-`

        # Bind commands.
        self.aMenu.add_separator()
        self.aMenu.add_command(label='Jump to main', command=self.jmp_main)
        self.properties_menu = Menu(self.aMenu)
        self.properties_menu.add_command(label='To Main Tab', command=lambda: self.properties_main(top_level=False))
        self.properties_menu.add_command(label='Separate Tab', command=self.properties_main)
        self.aMenu.add_cascade(label='Process Properties', menu=self.properties_menu)

    def get_item_from_table(self, table, value):
        '''
        This function serach for specific item in given table, if the item not found, return None
        :param table: the table database to search in
        :param value: the specific value to search (check if equals to the jmp_pid_index [the index of the pid column in the table])
        :return: item / None
        '''
        for item in table.get_all_children(table.tree, item="", only_opened=False):
            if str(table.tree.item(item[0])['values'][self.jmp_pid_index]) == str(value):
                return item[0]

    def jmp_main(self):
        '''
        Jump and select the specifig process.
        :return: None
        '''
        global main_table
        child_id = self.get_item_from_table(main_table, self.jmp_name or self.tree.item(self.tree.selection()[0])['values'][int(self.index_pid)])

        # Go and select the process (if exists, else alert the user).
        if child_id:
            main_table.tree.focus(child_id)
            main_table.tree.selection_set(child_id)
            main_table.tree.see(child_id)
            self.master.select(0)
        else:
            messagebox.showerror("Error", "This item doesn't exist", parent=self)

    def properties_main(self, top_level=True):
        '''
        Open process properties on selected item.
        :param top_level: None
        :return: None
        '''
        global main_table
        child_id = self.get_item_from_table(main_table, self.jmp_name or self.tree.item(self.tree.selection()[0])['values'][int(self.index_pid)])

        # Open the process properties (if exists, else alert the user).
        if child_id:
            main_table.OnDoubleClick(None, select=child_id, top_level=top_level)
        else:
            messagebox.showerror("Error", "This item doesn't exist", parent=self)

class Modules(NBTab, DllsTable):
    '''
    The Modules Treetable(treeview) tab
    '''
    def __init__(self, master, headers, data, jmp_pid_index=None, jmp_pid=None, index_pid=None, name=None, text_by_item=0, resize=False, display=None):
        NBTab.__init__(self, master, headers, data, jmp_pid_index, jmp_pid, index_pid, name, text_by_item, resize, display)
        DllsTable.__init__(self, master, self, headers, data, name, text_by_item, resize, display, pid=4)

class HelpMe(Frame):
    '''
    Text widget that display text(remove the support for the edit function)
    '''

    def __init__(self, master, display_text=HELP_ME, *args, **kwargs):
        Frame.__init__(self, master, *args, **kwargs)

        # Horizontal (x) Scroll bar
        xscrollbar = Scrollbar(self, orient=HORIZONTAL)
        xscrollbar.pack(side=BOTTOM, fill=X)

        # Vertical (y) Scroll Bar
        yscrollbar = Scrollbar(self)
        yscrollbar.pack(side=RIGHT, fill=Y)

        # Text Widget
        text = Text(self, wrap=NONE, state='disabled',
                    xscrollcommand=xscrollbar.set,
                    yscrollcommand=yscrollbar.set)
        # text.state(['readonly'])
        text.configure(state='normal')
        text.insert('1.0', display_text)
        text.configure(state='disabled')
        text.pack(expand=YES, fill=BOTH)

        # Configure the scrollbars
        xscrollbar.config(command=text.xview)
        yscrollbar.config(command=text.yview)

#endregion GUI

class VolExp(common.AbstractWindowsCommand):
    """Memory Explorer (GUI plugin)"""

    def __init__(self, config, not_from_saved=True, *args, **kwargs):
        global location, dump_dir, profile, api_key, vol_path
        global volself
        global done_run
        global root
        logging.getLogger('').setLevel(logging.WARNING + 1)
        opts = dict(config.opts)
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        self._config = config
        volself = self
        config.add_option('DUMP-DIR', short_option='D', default=None,
                          cache_invalidator=False,
                          help='Directory in which to dump executable files')
        config.add_option('SAVED-FILE', short_option='s', default=None,
                          cache_invalidator=False,
                          help='Saved file path')

        self._show_unnamed_handles = 'false'
        self._show_pe_strings = 'true'
        config.remove_option('SIZE')
        config.remove_option('silent')
        config.remove_option('SILENT')
        self.dict_options = {}
        self.threads = []
        if hasattr(config, "VOL_PATH"):
            self._vol_path = config.VOL_PATH
        else:
            config.VOL_PATH = self._vol_path = None

        if not_from_saved:
            done_run['file_path'] = self._config.LOCATION
            done_run['profile'] = self._config.PROFILE
            if not hasattr(config, "SAVED_FILE") or config.SAVED_FILE == None or config.SAVED_FILE=='':
                if root == None:
                    if not hasattr(self._config, 'SAVED_FILE'):
                        self._config.SAVED_FILE = ""
                    if not hasattr(self._config, "API_KEY"):
                        self._config.API_KEY = None
                    root = Tk()
                    self.img = tk.PhotoImage(data=ICON)
                    root.tk.call('wm', 'iconphoto', root._w, "-default", self.img)
                    while self._config.DUMP_DIR == None or self._vol_path == None:
                        if self._config.DUMP_DIR == None:
                            print '[-] please insert dump dir to continue.'
                        if self._vol_path == None:
                            print '[-] please insert volatility FILE path to continue.'
                        self.popup_options(root)#('ATZ')
                    root.subprocess = loading_start('Initial Plugin')

                    done_run['dump_dir'] = str(self._config.DUMP_DIR)

                self.kaddr_space = utils.load_as(self._config)
            else:
                # Check that this run from vol.py and not as portable
                if not hasattr(config,"_portable"):
                    self.calc_return = list(self.load(config.SAVED_FILE))

                    if not hasattr(self._config, "API_KEY"):
                        self._config.API_KEY = api_key
                    root = Tk()
                    self.img = tk.PhotoImage(data=ICON)
                    root.tk.call('wm', 'iconphoto', root._w, "-default", self.img)
                    while self._config.DUMP_DIR == None or self._vol_path == None:
                        if self._config.DUMP_DIR == None:
                            print '[-] please insert dump dir to continue.'
                        if self._vol_path == None:
                            print '[-] please insert volatility FILE path to continue.'
                        self.popup_options(root)  # ('ATZ')
                    root.subprocess = loading_start('Initial Plugin')

            # Support portable volexp
            self._config.opts = opts
        else:
            self.kaddr_space = utils.load_as(self._config)

        location = self._config.LOCATION
        dump_dir = self._config.DUMP_DIR
        profile = self._config.PROFILE
        api_key = self._config.API_KEY
        vol_path = self._vol_path
        self.get_all_plugins()

    def popup_options(self, event=None):
        '''
        This Function popup the options menu.
        '''
        global root
        data = {'Saved File': self._config.SAVED_FILE,
            'Memory File': self._config.LOCATION,
            'Memory Profile': self._config.PROFILE,
            'Dump-Dir': self._config.DUMP_DIR or '',
            'KDBG Address (for faster loading)': self._config.KDBG or '',
            'Show Unnamed Handles': self._show_unnamed_handles or 'False',
            'Show PE Strings': self._show_pe_strings or 'True',
            'Volatility File Path': self._vol_path or (sys.argv[0] if (('memtriage' in sys.argv[0].lower() or 'vol' in sys.argv[0].lower()) and not 'volexp' in sys.argv[0].lower()) else os.getcwd().replace(os.path.join('volatility', 'plugins'), r'{}vol.py'.format(os.sep))),
            'Virus Total API Key': self._config.API_KEY or ''}


        if event == root:
            tv = event
        else:
            tv = tk.Toplevel()
            tv.grab_set()
            x = root.winfo_x()
            y = root.winfo_y()
            tv.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))

        tv.resizable(False, False)
        self.app = Options(tv, data, False)
        self.app.live = True

        def on_exit():
            if tv == root:
                print '[:] Hope to see you again...\nBye Bye'
            tv.destroy()
            self.app.live = False

        tv.protocol("WM_DELETE_WINDOW", on_exit)
        tv.title('Options')

        if event == root:
            root.after(1000, self.app.Save)

        while self.app.live and tv.title() == 'Options':
            time.sleep(0.2)
            root.update_idletasks()
            root.update()

        if self.app.live:
            tv.withdraw() if root == tv else tv.destroy()
            self.set_options(self.app.user_dict)

    def set_options(self, dict):
        '''
        This Function get dictionary and set the configuration variables acording to that dictionary.
        '''
        global dump_dir, api_key, vol_path

        self.dict_options = dict

        for item in dict:
            if item == 'Dump-Dir':
                if os.path.exists(dict[item]):
                    self._config.DUMP_DIR = dict[item]
                    self._config.opts['dump_dir'] = dict[item]
                    dump_dir = dict[item]
                else:
                    messagebox.showerror("Error", "You must specify the Dump-Dir", parent=self)
                    return
            elif item == 'KDBG Address (for faster loading)':
                if dict[item] != '' and (isinstance(dict[item], int) or dict[item].isdigit()):
                    self._config.KDBG = int(dict[item])
                    self._config.opts['kdbg'] = int(dict[item])
                elif dict[item] != '':
                    messagebox.showerror("Error", "You most specify the KDBG-Address as int", parent=self)
                    return
            elif item == 'Show Unnamed Handles':
                if dict[item].lower() == 'true' or dict[item].lower() == 'false':
                    if 't' in dict[item].lower():
                        self._show_unnamed_handles = 'true'
                    else:
                        self._show_unnamed_handles = 'false'
                else:
                    messagebox.showerror("Error", "You most specify the Show Unnamed Handles as True | False..", parent=self)
                    return
            elif item == 'Show PE Strings':
                if dict[item].lower() == 'true' or dict[item].lower() == 'false':
                    if 't' in dict[item].lower():
                        self._show_pe_strings = 'true'
                    else:
                        self._show_pe_strings = 'false'
                else:
                    messagebox.showerror("Error", "You most specify the Show PE Strings as True | False..", parent=self)
                    return

            elif item == 'Volatility File Path':
                if os.path.isfile(dict[item]):
                    self._vol_path = dict[item]
                    vol_path = dict[item]
                else:
                    messagebox.showerror("Error", "You most specify the volatility file(vol.py\volatility.exe) as exist file..", parent=self)
                    return
            elif item == 'Virus Total API Key':
                self._config.API_KEY = dict[item]
                api_key = dict[item]

    def run_struct_analyze(self, struct_type, tree):
        '''
        get address and sent to teal struct analyze function.
        '''
        global queue
        global root
        item = tree.selection()[0]
        addr = tree.item(item)['values'][-1]
        if not addr or addr == -1:
            def show_message_func():
                messagebox.showerror("Error", "Unable to locate this struct address in memory ({})".format(struct_type), parent=root)

            queue.put((show_message_func, ()))
            return
        print "[+] Run Struct Analyze on {}, addr: {}".format(struct_type, addr)
        threading.Thread(target=run_struct_analyze, args=(struct_type, addr)).start()

    def write(self, addr, data, pid=4, prev_data_len=0):
        data = "{}{}".format(data, ' '*len(data)-int(prev_data_len) if len(data)-int(prev_data_len) > 0 else '')
        if pid == 4:
            result = kaddr_space.write(addr, data)
        else:
            result = process_bases[int(pid)]["proc"].get_process_address_space().write(addr, data)

        print "[=] The Write Operation:".format(str(result).replace('True', 'succsuse').replace('False', 'Failed'))

    def get_all_handles(self):
        '''
        This function get all the process handles to the process_handles global.
        '''

        import volatility.plugins.handles as handlesplugin
        global process_handles
        global done_run
        global lock

        # Add to job queue
        id = time.time()
        job_queue.put_alert((id, 'VolExp Search Handles', 'the volexp search all handles information', 'Running'))


        # https://blogs.msdn.microsoft.com/openspecification/2010/04/01/about-the-access_mask-structure/
        # https://rayanfam.com/topics/finding-the-real-access-rights-needed-by-handles/
        # https://rayanfam.com/topics/reversing-windows-internals-part1/
        GENERIC_ACCESS = {0x80000000 : 'GENERIC_READ',
                          0x40000000 : 'GENERIC_WRITE',
                          0x20000000 : 'GENERIC_EXECUTE',
                          0x10000000 : 'GENERIC_ALL'}

        ACCESS_MASK = {0x08000000: 'RESERVED(27)',
                       0x04000000: 'RESERVED(26)',
                       0x02000000: 'RESERVED(25)',
                       0x01000000: 'SACL_ACCESS',
                       0x00800000: 'RESERVED(23)',
                       0x00400000: 'RESERVED(22)',
                       0x00200000: 'RESERVED(21)',
                       0x00100000: 'SYNCHRONIZE',
                       0x00080000: 'WRITE_OWNER',
                       0x00040000: 'WRITE_DAC',
                       0x00020000: 'READ_DAC',
                       0x00010000: 'DELETE',
                       }

        SPECIFIC_ACCESS = {0x00000001: '<Unknown>(0x1)',
                           0x00000002: '<Unknown>(0x2)',
                            0x00000004: '<Unknown>(0x4)',
                            0x00000008: '<Unknown>(0x8)',
                            0x00000010: '<Unknown>(0x10)',
                            0x00000020: '<Unknown>(0x20)',
                            0x00000040: '<Unknown>(0x40)',
                            0x00000080: '<Unknown>(0x80)',
                            0x00000100: '<Unknown>(0x100)',
                            0x00000200: '<Unknown>(0x200)',
                            0x00000400: '<Unknown>(0x400)',
                            0x00000800: '<Unknown>(0x800)',
                            0x00001000: '<Unknown>(0x1000)',
                            0x00002000: '<Unknown>(0x2000)',
                            0x00004000: '<Unknown>(0x4000)',
                            0x00008000: '<Unknown>(0x8000)'}

        TEMPLATE_ACCESS = {
            'REGULAR':{
                0x00000001: '<Unknown>(0x1)',
                0x00000002: '<Unknown>(0x2)',
                0x00000004: '<Unknown>(0x4)',
                0x00000008: '<Unknown>(0x8)',
                0x00000010: '<Unknown>(0x10)',
                0x00000020: '<Unknown>(0x20)',
                0x00000040: '<Unknown>(0x40)',
                0x00000080: '<Unknown>(0x80)',
                0x00000100: '<Unknown>(0x100)',
                0x00000200: '<Unknown>(0x200)',
                0x00000400: '<Unknown>(0x400)',
                0x00000800: '<Unknown>(0x800)',
                0x00001000: '<Unknown>(0x1000)',
                0x00002000: '<Unknown>(0x2000)',
                0x00004000: '<Unknown>(0x4000)',
                0x00008000: '<Unknown>(0x8000)'
            },
            'SPECIFIC':{}
        }

        JOB_ACCESS = {
            'REGULAR': {
                0x00000001: 'JOB_OBJECT_ASSIGN_PROCESS ',
                0x00000002: 'JOB_OBJECT_SET_ATTRIBUTES ',
                0x00000004: 'JOB_OBJECT_QUERY ',
                0x00000008: 'JOB_OBJECT_TERMINATE ',
                0x00000010: 'JOB_OBJECT_SET_SECURITY_ATTRIBUTES ',
                0x00000020: '<Unknown>(0x20)',
                0x00000040: '<Unknown>(0x40)',
                0x00000080: '<Unknown>(0x80)',
                0x00000100: '<Unknown>(0x100)',
                0x00000200: '<Unknown>(0x200)',
                0x00000400: '<Unknown>(0x400)',
                0x00000800: '<Unknown>(0x800)',
                0x00001000: '<Unknown>(0x1000)',
                0x00002000: '<Unknown>(0x2000)',
                0x00004000: '<Unknown>(0x4000)',
                0x00008000: '<Unknown>(0x8000)'
            },
            'SPECIFIC': {0x1F001F: 'JOB_OBJECT_ALL_ACCESS '}
        }

        #
        TOKEN_ACCESS = {
            'REGULAR':{
                0x00000001: 'TOKEN_ASSIGN_PRIMARY',
                0x00000002: 'TOKEN_DUPLICATE',
                0x00000004: 'TOKEN_IMPERSONATE',
                0x00000008: 'TOKEN_QUERY',
                0x00000010: 'TOKEN_QUERY_SOURCE',
                0x00000020: 'TOKEN_ADJUST_PRIVILEGES',
                0x00000040: 'TOKEN_ADJUST_GROUPS',
                0x00000080: 'TOKEN_ADJUST_DEFAULT',
                0x00000100: '',
                0x00000200: '',
                0x00000400: '',
                0x00000800: '',
                0x00001000: '',
                0x00002000: '',
                0x00004000: '',
                0x00008000: ''
            },
            'SPECIFIC': {}
        }

        KEY_ACCESS = {
            'REGULAR':{
                0x00000001: 'KEY_QUERY_VALUE',
                0x00000002: 'KEY_SET_VALUE',
                0x00000004: 'KEY_CREATE_SUB_KEY',
                0x00000008: 'KEY_ENUMERATE_SUB_KEYS',
                0x00000010: 'KEY_NOTIFY',
                0x00000020: 'KEY_CREATE_LINK',
                0x00000040: '<Unknown>(0x40)',
                0x00000080: '<Unknown>(0x80)',
                0x00000100: 'KEY_WOW64_64KEY',
                0x00000200: 'KEY_WOW64_32KEY',
                0x00000400: '<Unknown>(0x400)',
                0x00000800: '<Unknown>(0x800)',
                0x00001000: '<Unknown>(0x1000)',
                0x00002000: '<Unknown>(0x2000)',
                0x00004000: '<Unknown>(0x4000)',
                0x00008000: '<Unknown>(0x8000)',
            },

            'SPECIFIC':{
                0x00F003F: 'KEY_ALL_ACCESS',
                0x0020006: 'KEY_WRITE',
                0x0020019: 'KEY_READ',
            }
        }

        #
        FILE_ACCESS = { #  Check if file  | directory | namedpipe: https://docs.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants
            'FILE_ACCESS':{
                    'REGULAR':{
                        0x00000001: 'FILE_READ_DATA',
                        0x00000002: 'FILE_WRITE_DATA',
                        0x00000004: 'CREATE_SUB_KEY',
                        0x00000008: 'FILE_READ_EA',
                        0x00000010: 'FILE_WRITE_EA',
                        0x00000020: 'FILE_EXECUTE',
                        0x00000040: 'FILE_DELETE_CHILD',
                        0x00000080: 'FILE_READ_ATTRIBUTES',
                        0x00000100: 'FILE_WRITE_ATTRIBUTES',
                        0x00000200: '',
                        0x00000400: '',
                        0x00000800: '',
                        0x00001000: '',
                        0x00002000: '',
                        0x00004000: '',
                        0x00008000: ''},
                    'SPECIFIC': {}# FILE_ALL_ACCESS
            },
            'DIR_ACCESS':{
                'REGULAR': {
                    0x00000001: 'FILE_LIST_DIRECTORY',
                    0x00000002: 'FILE_ADD_FILE',
                    0x00000004: 'FILE_ADD_SUBDIRECTORY',
                    0x00000008: '<Unknown>(0x8)',
                    0x00000010: '<Unknown>(0x10)',
                    0x00000020: 'FILE_TRAVERSE',
                    0x00000040: '<Unknown>(0x40)',
                    0x00000080: '<Unknown>(0x80)',
                    0x00000100: '<Unknown>(0x100)',
                    0x00000200: '<Unknown>(0x200)',
                    0x00000400: '<Unknown>(0x400)',
                    0x00000800: '<Unknown>(0x800)',
                    0x00001000: '<Unknown>(0x1000)',
                    0x00002000: '<Unknown>(0x2000)',
                    0x00004000: '<Unknown>(0x4000)',
                    0x00008000: '<Unknown>(0x8000)'
                },
                'SPECIFIC': {}
            },
            'PIPE_ACCESS':{
                'REGULAR':{
                    0x00000001: 'PIPE_ACCESS_INBOUND',
                    0x00000002: 'PIPE_ACCESS_OUTBOUND',
                    0x00000004: '<Unknown>(0x4)', # FILE_CREATE_PIPE_INSTANCE
                    0x00000008: '<Unknown>(0x8)',
                    0x00000010: '<Unknown>(0x10)',
                    0x00000020: '<Unknown>(0x20)',
                    0x00000040: '<Unknown>(0x40)',
                    0x00000080: '<Unknown>(0x80)',
                    0x00000100: '<Unknown>(0x100)',
                    0x00000200: '<Unknown>(0x200)',
                    0x00000400: '<Unknown>(0x400)',
                    0x00000800: '<Unknown>(0x800)',
                    0x00001000: '<Unknown>(0x1000)',
                    0x00002000: '<Unknown>(0x2000)',
                    0x00004000: '<Unknown>(0x4000)',
                    0x00008000: '<Unknown>(0x8000)'
                },
            'SPECIFIC': {0x00000003: 'PIPE_ACCESS_DUPLEX '}
            }
        }

        #
        DESKTOP_ACCESS = {
            'REGULAR':{
                0x00000001: 'DESKTOP_READOBJECTS',
                0x00000002: 'DESKTOP_CREATEWINDOW',
                0x00000004: 'DESKTOP_CREATEMENU',
                0x00000008: 'DESKTOP_HOOKCONTROL',
                0x00000010: 'DESKTOP_JOURNALRECORD',
                0x00000020: 'DESKTOP_JOURNALPLAYBACK',
                0x00000040: 'DESKTOP_ENUMERATE',
                0x00000080: 'DESKTOP_WRITEOBJECTS',
                0x00000100: 'DESKTOP_SWITCHDESKTOP',
                0x00000200: '<Unknown>(0x200)',
                0x00000400: '<Unknown>(0x400)',
                0x00000800: '<Unknown>(0x800)',
                0x00001000: '<Unknown>(0x1000)',
                0x00002000: '<Unknown>(0x2000)',
                0x00004000: '<Unknown>(0x4000)',
                0x00008000: '<Unknown>(0x8000)'
            },
            'SPECIFIC': {}
        }

        ##
        DIRECTORY_ACCESS = { # 3 query traverse
            'REGULAR':{
                0x00000001: 'QUERY',
                0x00000002: 'TRAVERSE',
                0x00000004: 'CREATE_OBJECT',
                0x00000008: 'CREATE_SUBDIRECTORY',
                0x00000010: '<Unknown>(0x10)',
                0x00000020: '<Unknown>(0x20)',
                0x00000040: '<Unknown>(0x40)',
                0x00000080: '<Unknown>(0x80)',
                0x00000100: '<Unknown>(0x100)',
                0x00000200: '<Unknown>(0x200)',
                0x00000400: '<Unknown>(0x400)',
                0x00000800: '<Unknown>(0x800)',
                0x00001000: '<Unknown>(0x1000)',
                0x00002000: '<Unknown>(0x2000)',
                0x00004000: '<Unknown>(0x4000)',
                0x00008000: '<Unknown>(0x8000)'
            },
            'SPECIFIC': {0x000F000F: 'DIRECTORY_ALL_ACCESS'}
        }

        PROCESS_ACCESS = {
            'REGULAR':{
                0x00000001: 'PROCESS_TERMINATE',
                0x00000002: 'PROCESS_CREATE_THREAD',
                0x00000004: '<Unknown>(0x4)',
                0x00000008: 'PROCESS_VM_OPERATION',
                0x00000010: 'PROCESS_VM_READ',
                0x00000020: 'PROCESS_VM_WRITE',
                0x00000040: 'PROCESS_DUP_HANDLE',
                0x00000080: 'PROCESS_CREATE_PROCESS',
                0x00000100: 'PROCESS_SET_QUOTA',
                0x00000200: 'PROCESS_SET_INFORMATION',
                0x00000400: 'PROCESS_QUERY_INFORMATION',
                0x00000800: 'PROCESS_SUSPEND_RESUME',
                0x00001000: 'PROCESS_QUERY_LIMITED_INFORMATION',
                0x00002000: '<Unknown>(0x2000)',
                0x00004000: '<Unknown>(0x4000)',
                0x00008000: '<Unknown>(0x8000)'
            },
            'SPECIFIC': {
                0XFFFFF: 'PROCESS_ALL_ACCESS' # (SUPPORT > WINXP)
            }
        }

        THREAD_ACCESS = {
            'REGULAR':{
                0x00000001: 'THREAD_TERMINATE',
                0x00000002: 'THREAD_SUSPEND_RESUME',
                0x00000004: '<Unknown>(0x4)',
                0x00000008: 'THREAD_GET_CONTEXT',
                0x00000010: 'THREAD_SET_CONTEXT',
                0x00000020: 'THREAD_SET_INFORMATION',
                0x00000040: 'THREAD_QUERY_INFORMATION',
                0x00000080: 'THREAD_SET_THREAD_TOKEN',
                0x00000100: 'THREAD_IMPERSONATE',
                0x00000200: 'THREAD_DIRECT_IMPERSONATION',
                0x00000400: 'THREAD_SET_LIMITED_INFORMATION',
                0x00000800: 'THREAD_QUERY_LIMITED_INFORMATION',
                0x00001000: '<Unknown>(0x1000)',
                0x00002000: '<Unknown>(0x2000)',
                0x00004000: '<Unknown>(0x4000)',
                0x00008000: '<Unknown>(0x8000)'
            },
            'SPECIFIC': {0x001FFFFF: 'THREAD_ALL_ACCESS'}
        }

        WINSTA_ACCESS = {
            'REGULAR':{
                0x00000001: 'WINSTA_ENUMDESKTOPS',
                0x00000002: 'WINSTA_READATTRIBUTES',
                0x00000004: 'WINSTA_ACCESSCLIPBOARD',
                0x00000008: 'WINSTA_CREATEDESKTOP',
                0x00000010: 'WINSTA_WRITEATTRIBUTES',
                0x00000020: 'WINSTA_ACCESSGLOBALATOMS',
                0x00000040: 'WINSTA_EXITWINDOWS',
                0x00000080: '<Unknown>(0x80)',
                0x00000100: 'WINSTA_ENUMERATE',
                0x00000200: 'WINSTA_READSCREEN',
                0x00000400: '<Unknown>(0x400)',
                0x00000800: '<Unknown>(0x800)',
                0x00001000: '<Unknown>(0x1000)',
                0x00002000: '<Unknown>(0x2000)',
                0x00004000: '<Unknown>(0x4000)',
                0x00008000: '<Unknown>(0x8000)'
            },
            'SPECIFIC': {0x37F: 'WINSTA_ALL_ACCESS'}
        }

        SECTION_ACCESS = {
            'REGULAR':{
                0x00000001: 'QUERY',
                0x00000002: 'MAP_WRITE',
                0x00000004: 'MAP_READ',
                0x00000008: '<Unknown>(0x8)',
                0x00000010: '<Unknown>(0x10)',
                0x00000020: '<Unknown>(0x20)',
                0x00000040: '<Unknown>(0x40)',
                0x00000080: '<Unknown>(0x80)',
                0x00000100: '<Unknown>(0x100)',
                0x00000200: '<Unknown>(0x200)',
                0x00000400: '<Unknown>(0x400)',
                0x00000800: '<Unknown>(0x800)',
                0x00001000: '<Unknown>(0x1000)',
                0x00002000: '<Unknown>(0x2000)',
                0x00004000: '<Unknown>(0x4000)',
                0x00008000: '<Unknown>(0x8000)'
            },
            'SPECIFIC': {0x000F001F: 'SECTION_ALL_ACCESS'}
        }

        SYMLINK_ACCESS = {
            'REGULAR':{
                0x00000001: '<Unknown>(0x1)',
                0x00000002: '<Unknown>(0x2)',
                0x00000004: '<Unknown>(0x4)',
                0x00000008: '<Unknown>(0x8)',
                0x00000010: '<Unknown>(0x10)',
                0x00000020: '<Unknown>(0x20)',
                0x00000040: '<Unknown>(0x40)',
                0x00000080: '<Unknown>(0x80)',
                0x00000100: '<Unknown>(0x100)',
                0x00000200: '<Unknown>(0x200)',
                0x00000400: '<Unknown>(0x400)',
                0x00000800: '<Unknown>(0x800)',
                0x00001000: '<Unknown>(0x1000)',
                0x00002000: '<Unknown>(0x2000)',
                0x00004000: '<Unknown>(0x4000)',
                0x00008000: '<Unknown>(0x8000)'
            },
            'SPECIFIC': {}
        }

        ETW_ACCESS = {
            'REGULAR':{
                0x00000001: '<Unknown>(0x1)',
                0x00000002: '<Unknown>(0x2)',
                0x00000004: '<Unknown>(0x4)',
                0x00000008: '<Unknown>(0x8)',
                0x00000010: '<Unknown>(0x10)',
                0x00000020: '<Unknown>(0x20)',
                0x00000040: '<Unknown>(0x40)',
                0x00000080: '<Unknown>(0x80)',
                0x00000100: '<Unknown>(0x100)',
                0x00000200: '<Unknown>(0x200)',
                0x00000400: '<Unknown>(0x400)',
                0x00000800: '<Unknown>(0x800)',
                0x00001000: '<Unknown>(0x1000)',
                0x00002000: '<Unknown>(0x2000)',
                0x00004000: '<Unknown>(0x4000)',
                0x00008000: '<Unknown>(0x8000)'
            },
            'SPECIFIC': {}
        }

        ALPC_ACCESS = {
            'REGULAR':{
                0x00000001: '<Unknown>(0x1)',
                0x00000002: '<Unknown>(0x2)',
                0x00000004: '<Unknown>(0x4)',
                0x00000008: '<Unknown>(0x8)',
                0x00000010: '<Unknown>(0x10)',
                0x00000020: '<Unknown>(0x20)',
                0x00000040: '<Unknown>(0x40)',
                0x00000080: '<Unknown>(0x80)',
                0x00000100: '<Unknown>(0x100)',
                0x00000200: '<Unknown>(0x200)',
                0x00000400: '<Unknown>(0x400)',
                0x00000800: '<Unknown>(0x800)',
                0x00001000: '<Unknown>(0x1000)',
                0x00002000: '<Unknown>(0x2000)',
                0x00004000: '<Unknown>(0x4000)',
                0x00008000: '<Unknown>(0x8000)'
            },
            'SPECIFIC': {0x1f0001: 'ALPC_ALL_ACCESS'}
        }

        EVENT_ACCESS = {
            'REGULAR': {
                0x00000001: '<Unknown>(0x1)',
                0x00000002: 'EVENT_MODIFY_STATE',
                0x00000004: '<Unknown>(0x4)',
                0x00000008: '<Unknown>(0x8)',
                0x00000010: '<Unknown>(0x10)',
                0x00000020: '<Unknown>(0x20)',
                0x00000040: '<Unknown>(0x40)',
                0x00000080: '<Unknown>(0x80)',
                0x00000100: '<Unknown>(0x100)',
                0x00000200: '<Unknown>(0x200)',
                0x00000400: '<Unknown>(0x400)',
                0x00000800: '<Unknown>(0x800)',
                0x00001000: '<Unknown>(0x1000)',
                0x00002000: '<Unknown>(0x2000)',
                0x00004000: '<Unknown>(0x4000)',
                0x00008000: '<Unknown>(0x8000)'
            },
            'SPECIFIC': {0x1F0003: 'EVENT_ALL_ACCESS'}
        }

        IOC_ACCESS = {
            'REGULAR':{
                0x00000001: '<Unknown>(0x1)',
                0x00000002: '<Unknown>(0x2)',
                0x00000004: '<Unknown>(0x4)',
                0x00000008: '<Unknown>(0x8)',
                0x00000010: '<Unknown>(0x10)',
                0x00000020: '<Unknown>(0x20)',
                0x00000040: '<Unknown>(0x40)',
                0x00000080: '<Unknown>(0x80)',
                0x00000100: '<Unknown>(0x100)',
                0x00000200: '<Unknown>(0x200)',
                0x00000400: '<Unknown>(0x400)',
                0x00000800: '<Unknown>(0x800)',
                0x00001000: '<Unknown>(0x1000)',
                0x00002000: '<Unknown>(0x2000)',
                0x00004000: '<Unknown>(0x4000)',
                0x00008000: '<Unknown>(0x8000)'
            },
            'SPECIFIC': {}
        }

        MUTANT_ACCESS = {
            'REGULAR':{
                0x00000001: 'MUTEX_MODIFY_STATE',
                0x00000002: '<Unknown>(0x2)',
                0x00000004: '<Unknown>(0x4)',
                0x00000008: '<Unknown>(0x8)',
                0x00000010: '<Unknown>(0x10)',
                0x00000020: '<Unknown>(0x20)',
                0x00000040: '<Unknown>(0x40)',
                0x00000080: '<Unknown>(0x80)',
                0x00000100: '<Unknown>(0x100)',
                0x00000200: '<Unknown>(0x200)',
                0x00000400: '<Unknown>(0x400)',
                0x00000800: '<Unknown>(0x800)',
                0x00001000: '<Unknown>(0x1000)',
                0x00002000: '<Unknown>(0x2000)',
                0x00004000: '<Unknown>(0x4000)',
                0x00008000: '<Unknown>(0x8000)'
            },
            'SPECIFIC': {0x1F0001: 'MUTEX_ALL_ACCESS'}
        }

        SEMAPHORE_ACCESS = {
            'REGULAR':{
                0x00000001: '<Unknown>(0x1)',
                0x00000002: 'SEMAPHORE_MODIFY_STATE',
                0x00000004: '<Unknown>(0x4)',
                0x00000008: '<Unknown>(0x8)',
                0x00000010: '<Unknown>(0x10)',
                0x00000020: '<Unknown>(0x20)',
                0x00000040: '<Unknown>(0x40)',
                0x00000080: '<Unknown>(0x80)',
                0x00000100: '<Unknown>(0x100)',
                0x00000200: '<Unknown>(0x200)',
                0x00000400: '<Unknown>(0x400)',
                0x00000800: '<Unknown>(0x800)',
                0x00001000: '<Unknown>(0x1000)',
                0x00002000: '<Unknown>(0x2000)',
                0x00004000: '<Unknown>(0x4000)',
                0x00008000: '<Unknown>(0x8000)'
            },
            'SPECIFIC': {0x1F0003: 'SEMAPHORE_ALL_ACCESS'}
        }

        TIMER_ACCESS = {
            'REGULAR':{
                0x00000001: 'TIMER_QUERY_STATE',
                0x00000002: 'TIMER_MODIFY_STATE',
                0x00000004: '<Unknown>(0x4)',
                0x00000008: '<Unknown>(0x8)',
                0x00000010: '<Unknown>(0x10)',
                0x00000020: '<Unknown>(0x20)',
                0x00000040: '<Unknown>(0x40)',
                0x00000080: '<Unknown>(0x80)',
                0x00000100: '<Unknown>(0x100)',
                0x00000200: '<Unknown>(0x200)',
                0x00000400: '<Unknown>(0x400)',
                0x00000800: '<Unknown>(0x800)',
                0x00001000: '<Unknown>(0x1000)',
                0x00002000: '<Unknown>(0x2000)',
                0x00004000: '<Unknown>(0x4000)',
                0x00008000: '<Unknown>(0x8000)'
            },
            'SPECIFIC': {0x1F0003: 'TIMER_ALL_ACCESS'}
        }

        # Update all tables. (of the supported specific access masks.
        ACCESS_MASK.update(GENERIC_ACCESS)
        #ACCESS_MASK.update(SPECIFIC_ACCESS)
        TOKEN_ACCESS['REGULAR'].update(ACCESS_MASK)
        #PIPE_ACCESS['REGULAR'].update(ACCESS_MASK)
        KEY_ACCESS['REGULAR'].update(ACCESS_MASK)
        FILE_ACCESS['FILE_ACCESS']['REGULAR'].update(ACCESS_MASK)
        FILE_ACCESS['DIR_ACCESS']['REGULAR'].update(ACCESS_MASK)
        FILE_ACCESS['PIPE_ACCESS']['REGULAR'].update(ACCESS_MASK)
        DESKTOP_ACCESS['REGULAR'].update(ACCESS_MASK)
        DIRECTORY_ACCESS['REGULAR'].update(ACCESS_MASK)
        PROCESS_ACCESS['REGULAR'].update(ACCESS_MASK)
        THREAD_ACCESS['REGULAR'].update(ACCESS_MASK)
        WINSTA_ACCESS['REGULAR'].update(ACCESS_MASK)
        SECTION_ACCESS['REGULAR'].update(ACCESS_MASK)
        SYMLINK_ACCESS['REGULAR'].update(ACCESS_MASK)
        ETW_ACCESS['REGULAR'].update(ACCESS_MASK)
        ALPC_ACCESS['REGULAR'].update(ACCESS_MASK)
        EVENT_ACCESS['REGULAR'].update(ACCESS_MASK)
        IOC_ACCESS['REGULAR'].update(ACCESS_MASK)
        MUTANT_ACCESS['REGULAR'].update(ACCESS_MASK)
        SEMAPHORE_ACCESS['REGULAR'].update(ACCESS_MASK)
        TIMER_ACCESS['REGULAR'].update(ACCESS_MASK)
        JOB_ACCESS['REGULAR'].update(ACCESS_MASK)

        # Map object name to specific dictionary of access.
        ACCESS_TYPE = {'Token': TOKEN_ACCESS,
                       #'Pipe': PIPE_ACCESS,
                       'Key': KEY_ACCESS,
                       'File': FILE_ACCESS,
                       'Desktop': DESKTOP_ACCESS,
                       'Directory': DIRECTORY_ACCESS,
                       'Process': PROCESS_ACCESS,
                       'Thread': THREAD_ACCESS,
                       'WindowStation': WINSTA_ACCESS,
                       'Section': SECTION_ACCESS,
                       'SymbolicLink': SYMLINK_ACCESS,
                       'EtwRegistration': ETW_ACCESS,
                       'ALPC Port': ALPC_ACCESS,
                       'Event': EVENT_ACCESS,
                       'IoCompletion': IOC_ACCESS,
                       'Mutant': MUTANT_ACCESS,
                       'Semaphore': SEMAPHORE_ACCESS,
                       'Timer': TIMER_ACCESS,
                       'Job': JOB_ACCESS,
                       }
        def check_special_types(type, value):
            '''
            Return the right dictionary access mask
            :param type: handle_type
            :param value: handle_value
            :return: DICT_ACCESS
            '''

            # File represent also pipes and ntfs directories
            if type == 'File':

                # If this is pipe named handle
                if r'\Device\NamedPipe' in value:
                    return FILE_ACCESS['PIPE_ACCESS']

                # Try to check if this is file or directory
                elif r'\Device\HarddiskVolume' in value and '.' in value.split('\\')[-1]:
                    return FILE_ACCESS['FILE_ACCESS']
                else:
                    return FILE_ACCESS['DIR_ACCESS']
            else:
                return ACCESS_TYPE[type]

        handles_conf = conf.ConfObject()

        # Define conf
        handles_conf.remove_option('SAVED-FILE')
        handles_conf.readonly = {}
        handles_conf.PROFILE = self._config.PROFILE
        handles_conf.LOCATION = self._config.LOCATION
        handles_conf.KDBG = self._config.KDBG
        handles_plug = handlesplugin.Handles(handles_conf)

        # Run in thread so the program wont crush from debug.error inside |
        #																  V
        # debug.error make the programs stop as result of taskmods filtertask function because it get the -p(profile) as -p(pid) and the pid is profile witch is not valid happend only on windows 10(check on 7)
        handles_gen = handles_plug.calculate()
        all_handles = handles_gen

        # Go all over the handels and insert them to the global process_handles.
        for handle_pid, handle, handle_type, handle_value in all_handles:

            handle_pid = int(handle_pid) # memtriage realtime problem, so i want to create new integer and not a pointer to a reference.

            # Create a list in the process_handles[pid] (if not exist)
            if not process_handles.has_key(int(handle_pid)):
                process_handles[int(handle_pid)] = []

            access = int(handle.GrantedAccess)
            access_temp = int(access)
            access_translate = ''
            if handle_type == 'File':
                file_handle = handle.dereference_as('_FILE_OBJECT')
                share_flags = file_handle.access_string()
            else:
                share_flags = ''

            # Check specific access.
            if ACCESS_TYPE.has_key(handle_type):
                access_mask = check_special_types(handle_type, handle_value)

                # Go over specific access right (a or between two or more regulare access)
                for c_access in sorted(access_mask['SPECIFIC'], reverse=True):
                    if access_temp & c_access and access_temp >= c_access:
                        access_translate += '{}, '.format(access_mask['SPECIFIC'][c_access])
                        access_temp -= c_access

                        # If object all access than stop go all over the other rights.
                        if 'ALL_ACCESS' in access_mask['SPECIFIC'][c_access]:
                            break
                else:

                    # Go over regular access right
                    for c_access in access_mask['REGULAR']:
                        if access_temp & c_access and access_temp >= c_access:
                            access_translate += '{}, '.format(access_mask['REGULAR'][c_access])

                # Remove the ", " in the end of the string.
                if len(access_translate) > 2:
                    access_translate = access_translate[:-2]

            # Add the handle information to the dictionary
            # Handle Information                      Type       | Value      | Share Flags| Handle            | Access| Access translate| Handle Virtual Offset  | Object Physical Address
            process_handles[int(handle_pid)].append((handle_type, handle_value, share_flags, int(handle.HandleValue), access, access_translate, handle.Body.obj_offset , handle.obj_vm.vtop(handle.Body.obj_offset)))

        done_run['process_handles'] = process_handles
        job_queue.put_alert((id, 'Get Handles', 'the volexp search all handles information', 'Done'))

    def get_all_plugins(self):
        global all_plugins
        #global done_run

        # Get all plugins
        plugins = registry.get_plugin_classes(commands.Command, lower=True)

        # Go all over the plugins.
        for plugin_name in plugins:

            # Check that this is good plugin to run.
            if not plugin_name.startswith(('linux_', 'mac_', 'volshell')):
                all_plugins[1].append(plugin_name)

        file_name = os.path.split(self._vol_path)[1]
        if file_name.lower() in ['memtriage.exe', 'memtriage.py', 'memtriage', 'mem.py', 'mem.exe', 'mem']:
            self.is_memtriage = True
        else:
            self.is_memtriage = False

        all_plugins[0] = self._config.get_value('plugins') or self._vol_path.replace(file_name, os.path.join('volatility', 'plugins'))# plugins_dir if plugins_dir != '' else os.path.dirname(os.path.abspath(__file__))
        all_plugins[1].sort()

    def return_pstree(self):
        '''
        This function create process tree
        :return: [(pid, pad)...]
        '''
        global lock

        proc_list = []
        address_space = self.kaddr_space
        pslist = {}
        pss = tasks.pslist(address_space)

        # Get the task list.
        for task in pss:
            pslist[(int(task.UniqueProcessId))] = task

        # Find the root of some pid
        def find_root(pid_dict, pid):

            seen = set()

            # While there is more processes.
            while pid in pid_dict and pid not in seen:
                seen.add(pid)
                pid = int(pid_dict[pid].InheritedFromUniqueProcessId)

            return pid

        def draw_branch(pad, inherited_from, inherited_time):
            global lock

            # Go all over the processes.
            for task in pslist.values():

                # Check if is child by checking the ppid with all other the pid(from the process list) and also that the parent created time is less than the child created time.
                if task.InheritedFromUniqueProcessId == inherited_from and inherited_time <= task.CreateTime:

                    proc_list.append((task, pad))

                    # Added Because Python Ituration Problem(the try except removed).
                    if pslist.has_key(int(task.UniqueProcessId)):
                        del pslist[int(task.UniqueProcessId)]
                    else:
                        debug.warning(
                            "Iteration Problem OR The PID {0} PPID {1} has already been seen (recommended to check that on pslist)".format(
                                task.UniqueProcessId, task.InheritedFromUniqueProcessId))
                    draw_branch(pad + 1, task.UniqueProcessId, task.CreateTime)

        # Go all over the processes and create the process tree in the dictionary.
        while len(pslist.keys()) > 0:
            keys = pslist.keys()
            root = find_root(pslist, keys[0])
            ctime = pslist[root].CreateTime if root in pslist else float("-inf")#int(time.time())
            draw_branch(0, root, ctime)


        # Create good and sorted dictionary to work with.
        proc_list_ret = []
        roots = []
        for proc in proc_list:
            if proc[1] == 0:
                roots.append(int(proc[0].UniqueProcessId))

        sorted_roots = list(sorted(roots))
        for pid in sorted_roots:
            flag = False
            for proc in proc_list:
                with lock:
                    if (int(proc[0].UniqueProcessId)) == pid or flag:
                        flag = True
                        if proc[1] == 0 and not proc[0].UniqueProcessId == pid:
                            break
                        else:
                            proc_list_ret.append(proc)
        return proc_list_ret

    def get_proc_verinfo(self):
        '''
        Get process files information to files_info dictionary
        :return: None
        '''
        global files_info
        global done_run
        global lock

        # Add to job queue
        id = time.time()
        job_queue.put_alert((id, 'VolExp Search Files Metadata', 'Get files company name, version, realname...', 'Running'))

        verinfo_conf = conf.ConfObject()
        verinfo_conf.readonly = {}
        verinfo_conf.PROFILE = self._config.PROFILE
        verinfo_conf.LOCATION = self._config.LOCATION
        verinfo_conf.KDBG = self._config.KDBG
        verinfo_conf._kaddr_space = utils.load_as(verinfo_conf)

        task_list = tasks.pslist(verinfo_conf._kaddr_space)


        c_app = None

        # Go over processes
        for task in task_list:
            process_addr_space = task.get_process_address_space()

            # Go all over the process modules
            for module in task.get_load_modules():
                pefile = obj.Object("_IMAGE_DOS_HEADER", module.DllBase, process_addr_space)
                if pefile.is_valid() and module:
                    vinfo = pefile.get_version_info()
                    files_info[str(module.FullDllName).lower()] = {}

                    # Insert the data to the files_info["file_name"] -> [type] = value (if there is any data)
                    if vinfo:

                        # Remove this try when volatility fix this problem on new profiles.
                        try:
                            for type, value in vinfo.get_file_strings():
                                files_info[str(module.FullDllName).lower()][type] = value
                        except (ValueError, TypeError, AttributeError, obj.InvalidOffsetError):
                            pass # TypeError: unsupported operand type(s) for +: 'NoneType' and 'int', InvalidOffsetError: Invalid Address <addr>, instantiating Key <key>
        job_queue.put_alert((id, 'VolExp Search Files Metadata', 'Get files company name, version, realname...', 'Done'))
        done_run['files_info'] = files_info

    def impscan_func(self, pid):
        '''
        This function insert all the process impscan to process_imports
        :param pid:
        :return:
        '''
        import volatility.plugins.malware.impscan as impscan
        global process_imports
        global lock

        impscan_conf = copy.deepcopy(conf.ConfObject())
        impscan_conf.readonly = {}
        impscan_conf.PROFILE = self._config.PROFILE
        impscan_conf.LOCATION = self._config.LOCATION
        impscan_conf.remove_option('SIZE')
        impscan_conf.remove_option('silent')
        impscan_conf.remove_option('SAVED-FILE')
        print "on impscan_func with pid,",impscan_conf.PID
        task = process_bases[int(pid)]["proc"]
        process_imports[int(pid)] = []
        all_mods = task.get_load_modules()

        # Check if we can find any module load in this address space.
        if all_mods and list(all_mods):
            with lock:
                impscan_conf.PID = pid
                impScan = impscan.ImpScan(impscan_conf)
            impScanCalc = list(impScan.calculate())

            # Go all over the impscan and insert them to the process_imports.
            for iat, call, mod, func in impScanCalc:
                mod, func = impScan._original_import(str(mod.BaseDllName or ''), func)
                process_imports[int(pid)].append((iat, call, mod, func))
        else:
            print 'no modules for: {}'.format(task)

    def update_connections(self):
        '''
        This function update the process_connection global with process connection information.
        :param my_connections: netscan.calculate()
        :return: None
        '''
        global process_connections
        global done_run

        # Add to job queue
        id = time.time()
        job_queue.put_alert((id, 'VolExp Search Connections', 'Search for network activity on the system', 'Running'))

        # Create the connection config
        my_connections_conf = conf.ConfObject()
        my_connections_conf.readonly = {}
        my_connections_conf.PROFILE = self._config.PROFILE
        my_connections_conf.LOCATION = self._config.LOCATION
        my_connections_conf.KDBG = self._config.KDBG

        # If windows xp
        if int(self.kaddr_space.profile.metadata.get('major')) <= 5:
            from volatility.plugins import connscan, sockscan
            from volatility import protos

            my_sock_plug = [(str(o.obj_offset), int(o.Pid), int(o.LocalPort), int(o.Protocol),
                             str(protos.protos.get(o.Protocol.v(), "-")), str(o.LocalIpAddress),
                             str(o.CreateTime)) for o in sockscan.SockScan(my_connections_conf).calculate()]
            my_connections_plug = [(str(o.LocalIpAddress), int(o.LocalPort), str(o.RemoteIpAddress), int(o.RemotePort),
                                    int(o.Pid), str(o.obj_offset)) for o in connscan.ConnScan(my_connections_conf).calculate()]

            for sock_obj in my_sock_plug:
                pid = sock_obj[1]
                for con_obj in my_connections_plug:

                    # If pid and local port equals                                 not address 0.0.0.0 vs address.
                    if sock_obj[1] == con_obj[-2] and sock_obj[2] == con_obj[1]: # and sock_obj[-2] == con_obj[0]:
                        c_data = (sock_obj[1], sock_obj[4], '{}:{}'.format(con_obj[0], con_obj[1]), '{}:{}'.format(con_obj[2], con_obj[3]), 'Not Supported On Windows XP', sock_obj[-1], '{}, {}'.format(str(sock_obj[0]), str(con_obj[-1])))
                        my_connections_plug.remove(con_obj)
                        break
                else:
                    c_data = (sock_obj[1], sock_obj[4], '{}:{}'.format(sock_obj[-2], sock_obj[2]),
                              'Unable To Get Remote Address', 'Not Supported On Windows XP', sock_obj[-1],
                              str(sock_obj[0]))

                # init the process_connection[pid] to empty list (if there is nothing).
                if not process_connections.has_key(pid):
                    process_connections[pid] = []

                process_connections[pid].append(c_data)

            for con_obj in my_connections_plug:
                pid = con_obj[-2]
                c_data = (con_obj[-2], 'Unable To Get Protocol Name', '{}:{}'.format(con_obj[0], con_obj[1]),
                          '{}:{}'.format(con_obj[2], con_obj[3]), 'Not Supported On Windows XP', 'Unable To Get Created Time',
                          str(con_obj[-1]))

                # init the process_connection[pid] to empty list (if there is nothing).
                if not process_connections.has_key(pid):
                    process_connections[pid] = []

                process_connections[pid].append(c_data)

        else:
            import volatility.plugins.netscan as netscan
            my_connections_plug = netscan.Netscan(my_connections_conf)

            # Get all connections from netscan.calcuate()
            my_connections = my_connections_plug.calculate()

            # Go all the network information from netscan
            for net_obj, protocol, local_address, local_port, remote_address, remote_port, state in my_connections:
                if net_obj.Owner == None:
                    pid = 0
                else:
                    pid = int(net_obj.Owner.UniqueProcessId)

                # init the process_connection[pid] to empty list (if there is nothing).
                if not process_connections.has_key(pid):
                    process_connections[pid] = []
                process_connections[pid].append((str(pid), str(protocol), "{}:{}".format(local_address, local_port),
                                                 "{}:{}".format(remote_address, remote_port), str(state),
                                                 str(net_obj.CreateTime) if net_obj.CreateTime else '', (str(net_obj))))

        queue.put((self.subview_menu_bar.entryconfig, (7, ('**kwargs', {'background': self.menu_bg}))))

        done_run['process_connections'] = process_connections


        data = []

        # Gather all the process_connections information in list
        for proc in process_connections:
            data += process_connections[proc]

        # Insert the data to the treetable connection table.
        queue.put((self.network_table.insert_items, (data,)))
        self.frames['Network'] = self.network_table
        job_queue.put_alert((id, 'VolExp Search Connections', 'Search for network activity on the system', 'Done'))

    def update_properties(self):
        '''
        This function update the process_env_var and process_imports
        :param my_tasks: pslist
        :return: None
        '''
        global process_env_var
        global lock
        global done_run
        print "[+] update_properties"

        # Create the properties config (use to search environment variables and imports)
        properties_conf = conf.ConfObject()
        properties_conf.remove_option('SAVED-FILE')
        properties_conf.readonly = {}
        properties_conf.PROFILE = self._config.PROFILE
        properties_conf.LOCATION = self._config.LOCATION
        properties_conf.kaddr_space = utils.load_as(properties_conf)
        if hasattr(self._config, "KDBG") and self._config.KDBG: #memtri
            properties_conf.KDBG = self._config.KDBG

        my_tasks = list(tasks.pslist(properties_conf.kaddr_space))

        # Add to job queue
        id = time.time()
        job_queue.put_alert((id, 'VolExp Search Process Environment Variables ', 'Get all process environment variable', 'Running'))

        # Get all environment variables (if we don't have it from cache).
        if len(process_imports) == 0:

            # Go all over the task
            for task in my_tasks:
                with lock:
                    pid = int(task.UniqueProcessId)

                # insert the data to the process_env_var
                if not process_env_var.has_key(pid):
                    process_env_var[pid] = {}

                    # Get all task environment variable
                    task_env_vars = list(task.environment_variables())

                    # Go all over the environment variable and insert them to the process_env_var.
                    for env, var in task_env_vars:
                        process_env_var[int(task.UniqueProcessId)][env] = var

        done_run['process_env_var'] = process_env_var
        print "[+] Done Get Environment variables"
        job_queue.put_alert((id, 'VolExp Search Process Environment Variables ', 'Get all process environment variable', 'Done'))

        # Add to job queue
        id = time.time()
        job_queue.put_alert((id, 'VolExp Search Process Imports ', 'Get all process imports', 'Running'))

        # Get all processes imports.
        for task in my_tasks:
            task_pid = int(task.UniqueProcessId)

            # Skip all the cache imports
            if not process_imports.has_key(int(task_pid)):
                if task_pid == 4:
                    continue
                #print "get imports for:", task_pid
                # self.impscan_func(task_pid) conflict with the rest of the plugin
                self.get_imports(task, task_pid)
                #threading.Thread(target=self.impscan_func, args=(self._config.PID,)).start()
            else:
                pass#print '[+] loaded import from ', task_pid
        job_queue.put_alert((id, 'VolExp Search Process Environment Variables ', 'Get all process environment variable', 'Done'))
        done_run['process_imports'] = process_imports
        print "[+] Done Get Imports"

    def get_imports(self, task, pid):
        '''
        This function get the first load module imports
        The first load module is the executable file
        :param task: _EPROCESS of the task
        :param pid: pid
        :return: None
        '''
        global process_imports
        try:
            process_imports[int(pid)] = [(str(func_name), str(mod_name), int(addr),  int(hint))  for mod_name, hint, addr, func_name in task.get_load_modules().next().imports()]
        except StopIteration:
            process_imports[int(pid)] = []

    def svc_scan(self):
        """
        Get all services using svcscan plugin.
        """
        global service_dict
        global process_comments
        global done_run
        global queue

        import volatility.plugins.malware.svcscan as svcscan
        # Create the svc_scan config
        svscan_conf = conf.ConfObject()
        svscan_conf.readonly = {}
        svscan_conf.PROFILE = self._config.PROFILE
        svscan_conf.LOCATION = self._config.LOCATION
        svscan_conf.KDBG = self._config.KDBG
        svscan_plug = svcscan.SvcScan(svscan_conf)

        # Get all services from svcscan.calculate()
        svc_calc = svscan_plug.calculate()

        # Add to job queue
        id = time.time()
        job_queue.put_alert((id, 'VolExp Search Services Information ', 'Get all the services with related information (like offset, pid...)', 'Running'))

        # Go all over the svc_calc
        for svc in svc_calc:
            c_pid = int(svc.Pid) or '-'

            if not process_comments.has_key(c_pid): #memtri
                continue

            # Init the service_dict[pid] = list (if there is not list in there)
            if not service_dict.has_key(c_pid):
                service_dict[c_pid] = []

                # Set the process color to the process of this service.
                if isinstance(c_pid, int) and c_pid != -1:
                    queue.put((self.treetable.SetColorItem, ('light pink', None, c_pid)))
                    #if not process_comments['pidColor'].has_key(c_pid) and process_comments.has_key(c_pid):
                    process_comments[c_pid] += "(Colored in pink because this is a service)."
                    process_comments['pidColor'][c_pid] = 'light pink'
            service_dict[c_pid].append((str(svc.obj_offset),
                                        str(svc.Order),
                                        str(svc.Start),
                                        str(c_pid),
                                        str(svc.ServiceName.dereference()),
                                        str(svc.DisplayName.dereference()),
                                        str(svc.Type),
                                        str(svc.State),
                                        str(svc.Binary or '-')))  # svc

        # Change the menu colore to default
        def change_menu_color():
            self.view_menu_bar.entryconfig(7, background=self.menu_bg)
            self.subview_menu_bar.entryconfig(8, background=self.menu_bg)
        queue.put((change_menu_color, ()))

        done_run['service_dict'] = service_dict

        print '[+] Done get all services'


        data = []

        # Gather all the service_dict information in list
        for proc in service_dict:
            data += service_dict[proc]

        # Append the data to the service_table tree inside the Service tab.
        queue.put((self.service_table.insert_items, (data,)))
        self.frames['Network'] = self.service_table
        job_queue.put_alert((id, 'VolExp Search Services Information ', 'Get all the services with related information (like offset, pid...)', 'Done'))

    #Unused funciton
    def update_pfn_stuff(self, pfn_conf):
        global pfn_stuff
        global lock

        #kdbg = None
        print 'Start PFN with thread {}'.format(threading.current_thread().ident)
        self.kdbg = win32.tasks.get_kdbg(pfn_conf.kaddr_space)
        my_tasks = list(self.kdbg.processes())#win32.tasks.pslist(pfn_conf.kaddr_space)

        pages_dict = {'MmBadPagesDetected':self.kdbg.MmBadPagesDetected,
        'MmModifiedPageListHead':self.kdbg.MmModifiedPageListHead,
        'MmResidentAvailablePages':self.kdbg.MmResidentAvailablePages,
        'MmFreePageListHead':self.kdbg.MmFreePageListHead,
        'MmStandbyPageListHead': self.kdbg.MmStandbyPageListHead,
        'MmModifiedNoWritePageListHead': self.kdbg.MmModifiedNoWritePageListHead,
        'MmZeroedPageListHead':self.kdbg.MmZeroedPageListHead}

        for page_list in pages_dict:
            pfnlist = obj.Object('_MMPFNLIST', pages_dict[page_list], self.kaddr_space)
            pfn_stuff[page_list] = int(pfnlist.Total)

        print pfn_stuff

        pfndb = int(self.kaddr_space.read(self.kdbg.MmPfnDatabase, 8)[::-1].encode("hex"), 16)

        for proc in range(len(my_tasks)):
            proc_id = my_tasks[proc].UniqueProcessId
            proc_addr_space = my_tasks[proc].get_process_address_space()
            if pfn_stuff.has_key(int(proc_id)):
                if pfn_stuff[int(proc_id)][-999] == 0:
                    pfn_stuff[int(proc_id)] = {-999:0 , 0:0, 1:0, 2:0, 3:0, 4:0, 5:0, 6:0, 7:0}
                    print 'search process id {} pfn info'.format(int(proc_id))
                else:
                    print 'load process id {} pfn info'.format(int(proc_id)) # We get all this information from the save pfn_stuff
                    continue
            #if proc_id == 4:
            #	continue

            for pte, va, size in proc_addr_space.get_available_pages(True):
                bin_pte = "{0:b}".format(pte)
                bin_pte = (64 - len(bin_pte)) * "0" + bin_pte if len(bin_pte) < 64 else bin_pte
                bin_pte = bin_pte[::-1]
                pa = bin_pte[12:39][::-1]
                pa = int(pa, 2)
                pfn_offset = int(pa)
                val = pfndb + (pfn_offset*0x30)
                pfn_entry = obj.Object("_MMPFN", val, proc_addr_space)
                if not pfn_stuff.has_key(int(proc_id)):
                    pfn_stuff[int(proc_id)] = {-999:0, 0:0, 1:0, 2:0, 3:0, 4:0, 5:0, 6:0, 7:0}
                try:
                    if pfn_stuff[int(proc_id)].has_key(int(pfn_entry.u3.e1.Priority)):
                        pfn_stuff[int(proc_id)][int(pfn_entry.u3.e1.Priority)] += 1
                except Exception as ex:
                    #print ex
                    #print pfn_stuff
                    pass

            pfn_stuff[int(proc_id)][-999] = 1 # Flag that indicate we done search this process

        print 'Done PFN'
        print pfn_stuff
        print sys.getsizeof(pfn_stuff)
        print 'Done PFN'

    def mft_parser(self):
        '''
        This function set the mft_explorer global by running the mftparsergui plugin with the -M yes (get the data as dict).
        :return: None
        '''
        global mft_explorer
        global done_run
        global lock

        # Create a temp file name to dump the information
        file_name = os.path.join(self._config.DUMP_DIR, 'mft_parser{}'.format(time.time()))

        # Get the command line according to if its memtriage or volatility
        if self.is_memtriage:
            command_line = r'"{}" "{}" --plugins=mftparsergui -M "{}"'.format(sys.executable, self._vol_path, file_name)
        else:

            # Get the file path and profile
            with lock:
                file_path = urllib.url2pathname(volself._config.location[7:])
                profile = self._config.PROFILE
            command_line = r'"{}" "{}" -f "{}" --profile={} mftparsergui -M "{}"'.format(sys.executable, self._vol_path, file_path, profile, file_name)

        # Add to job queue
        id = time.time()
        job_queue.put_alert((id, 'Volexp Search MFT Data', command_line, 'Running'))

        # Run the command and wait for output
        # Try to run this command (some profile my not support scanning so alert the user if we failed)
        try:
            proc = subprocess.check_output(command_line)
        except (subprocess.CalledProcessError, OSError, EOFError):
            try:
                proc = subprocess.Popen([command_line],
                                        shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                proc = proc.communicate()[0]
            except (subprocess.CalledProcessError, OSError, EOFError):
                print
                "[-] Volatility don't fully support this version (mft parser failed)"
                return

        # Parse the data to mft_explorer
        with open(file_name, 'rb') as mft_info_data:
            mft_explorer = pickle.load(mft_info_data)
        os.remove(file_name)

        # Change the menu colore to default
        def change_menu_color():
            self.view_menu_bar.entryconfig(3, background=self.menu_bg)
            self.subview_menu_bar.entryconfig(1, background=self.menu_bg)
        queue.put((change_menu_color, ()))

        # Insert the data to the done_run as well
        done_run['mft_explorer'] = mft_explorer

        job_queue.put_alert((id, 'Volexp Search MFT Data', command_line, 'Done'))
        print "[+] mft_explorer Done"

    def file_scan(self):
        '''
        This function set the file_scan global by running the filescangui plugin with the -M yes (get the data as dict).
        :return: None
        '''
        global files_scan
        global done_run
        global lock

        # Create a temp file name to dump the information
        file_name = os.path.join(self._config.DUMP_DIR, 'file_scan{}'.format(time.time()))

        # Get the command line according to if its memtriage or volatility
        if self.is_memtriage:
            command_line = r'"{}" "{}" --plugins=filescangui -M "{}"'.format(sys.executable, self._vol_path, file_name)
        else:

            # Get the file path and profile
            with lock:
                file_path = urllib.url2pathname(volself._config.location[7:])
                profile = self._config.PROFILE
            command_line = r'"{}" "{}" -f "{}" --profile={} filescangui -M "{}"'.format(sys.executable, self._vol_path, file_path, profile, file_name)

        # Add to job queue
        id = time.time()
        job_queue.put_alert((id, 'Volexp Search Files Data', command_line, 'Running'))

        # Try to run this command (some profile my not support scanning so alert the user if we failed)
        try:
            proc = subprocess.check_output(command_line)
        except (subprocess.CalledProcessError, OSError, EOFError):
            try:
                proc = subprocess.Popen([command_line],
                                        shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                proc = proc.communicate()[0]
            except (subprocess.CalledProcessError, OSError, EOFError):
                print
                "[-] Volatility don't fully support this version file scan failed"
                return

        # Parse the data to files_scan
        with open(file_name, 'rb') as file_info_data:
            files_scan = pickle.load(file_info_data)
        os.remove(file_name)

        # Change the menu colore to default
        def change_menu_color():
            self.view_menu_bar.entryconfig(4, background=self.menu_bg)
            self.subview_menu_bar.entryconfig(2, background=self.menu_bg)
        queue.put((change_menu_color, ()))

        # Insert the data to the done_run as well
        done_run['files_scan'] = files_scan

        job_queue.put_alert((id, 'Volexp Search Files Data', command_line, 'Done'))
        print "[+] file_scan Done"

    def win_obj(self):
        '''
        This function set the winobj_dict global by running the winobjgui plugin with the -M yes (get the data as dict).
        :return: None
        '''
        global winobj_dict
        global done_run
        global lock

        # Fix winobj win10 data if the user want to.
        if (self.kaddr_space.profile.metadata.get("major"), self.kaddr_space.profile.metadata.get("minor")) == (6, 4) and not self.kaddr_space.profile.has_type('_SECTION_OBJECT'):

            winobj_plugin_file_path = os.path.join(all_plugins[0], 'winobj.py')
            with open(winobj_plugin_file_path, 'rb') as winobj_plugin_file:
                winobj_plugin_code = winobj_plugin_file.read()

            def fix_win_obj(winobj_plugin_code):
                ans = messagebox.askyesnocancel("Notice",
                                                "winobj plugin have some problem in windows 10 do you want volexp to fix this plugin (by override the problem funcion)\nIf you choose no the we will be unnable to get the kernel objects data")
                # return if the user dont want to fix winobj
                if not ans:
                    self.winobj_lock.release()
                    return

                # Fix winobj code
                # New version of windows 10 does not have _SECTION_OBJECT object
                winobj_plugin_code = winobj_plugin_code.replace('elif obj_type == "Section":', 'elif obj_type == "Section" and addr_space.profile.has_type("_SECTION_OBJECT"):')

                with open(winobj_plugin_file_path, 'wb') as winobj_plugin_file:
                    winobj_plugin_file.write(winobj_plugin_code)

                reload(winobj)
                self.winobj_lock.release()

            # Check if winobj is not fixed already
            if not 'elif obj_type == "Section" and addr_space.profile.has_type("_SECTION_OBJECT"):' in winobj_plugin_code:
                self.winobj_lock = threading.Lock()
                self.winobj_lock.acquire()
                queue.put((fix_win_obj, (winobj_plugin_code, )))
                self.winobj_lock.acquire()

        # Create a temp file name to dump the information
        file_name = os.path.join(self._config.DUMP_DIR, 'winobj_data{}'.format(time.time()))

        # Get the command line according to if its memtriage or volatility
        if self.is_memtriage:
            command_line = r'"{}" "{}" --plugins=winobjgui -M "{}"'.format(sys.executable, self._vol_path, file_name)
        else:

            # Get the file path and profile
            with lock:
                file_path = urllib.url2pathname(volself._config.location[7:])
                profile = self._config.PROFILE
            command_line = r'"{}" "{}" -f "{}" --profile={} winobjgui -M "{}"'.format(sys.executable, self._vol_path, file_path, profile, file_name)

        # Add to job queue
        id = time.time()
        job_queue.put_alert((id, 'Volexp Search Objects Data', command_line, 'Running'))

        # Try to run this command (some profile my not support scanning so alert the user if we failed)
        try:
            proc = subprocess.check_output(command_line)
        except (subprocess.CalledProcessError, OSError, EOFError):
            try:
                proc = subprocess.Popen([command_line],
                                        shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                proc = proc.communicate()[0]
            except (subprocess.CalledProcessError, OSError, EOFError):
                print
                "[-] Volatility don't fully support this version (WinObj failed)"
                return

        # Parse the data to winobj_dict
        with open(file_name, 'rb') as obj_info_data:
            winobj_dict = pickle.load(obj_info_data)
        os.remove(file_name)

        # Change the menu colore to default
        def change_menu_color():
            self.view_menu_bar.entryconfig(5, background=self.menu_bg)
            self.subview_menu_bar.entryconfig(3, background=self.menu_bg)
        queue.put((change_menu_color, ()))

        # Insert the data to the done_run as well
        done_run['winobj_dict'] = winobj_dict

        job_queue.put_alert((id, command_line, 'Done'))
        print '[+] win_obj Done.'

    def order_right(self, dict, path_list, time):
        '''
        This function insert the key in the right place inside the dictionary
        :param dict: some parent dictionary of the key inside the reg_dict
        :param path_list: the key full name in a path list
        :param time: key access time
        :return: None
        '''
        global reg_dict

        # If the path_list is not empty its means that the dictionary is not the dictionary that represent the key information
        if len(path_list) > 0:

            # Some parent of the key.
            value = path_list.pop(0).title()

            # Insert this key to the dictionary (if this key is not already in there).
            if not dict.has_key(value):
                dict[value] = {}

            # Go deep inside untill len(path_list) == 0 that means that the dict represent the current key and we can insert the data to this key.
            self.order_right(dict[value], path_list, time)
        else:
            dict['|properties|'] = time

    def reg_hive_thread_builder(self, hive, user):
        '''
        This function go all over the keys inside this hive and insert them to the reg_dict (using self.order_right funciton)
        :param hive:
        :param user:
        :return:
        '''
        global reg_dict
        global lock

        print '[+] start regThread with user:{} hive:{}'.format(user, hive)
        reg_conf = conf.ConfObject()
        reg_conf.readonly = {}
        reg_conf.PROFILE = self._config.PROFILE
        reg_conf.LOCATION = self._config.LOCATION
        reg_conf.remove_option('ADDRESS')

        # Get regapi (volatiliry registry api)
        regapi = registryapi.RegistryApi(reg_conf)


        # Go all over the keys for this hive
        for key in regapi.reg_get_all_keys(hive, user):

            # If this hive inside know hives than get his real name.
            for know_hive in KNOWN_HIVES:

                # If this is the hive
                if know_hive in str(key[1]):
                    key = (key[0], str(key[1]).replace(know_hive, KNOWN_HIVES[know_hive]))

            # Get reg path
            reg_path = str(key[1]).replace('\\\\', '\\').split('\\')

            # Send the information for the self.order_right function to insert the data in the right place inside the reg_dict
            self.order_right(reg_dict, reg_path, key[0])

        #done_run['reg_dict'] = reg_dict
        print '[+] finish build {} hive'.format(hive)

        # A signal to know that we finish with this hive so if we save this and run this again we will not search for this information again.
        reg_dict['Finish build hives'].append(hive)

    def registry_keys(self):
        '''
        This function send one thread per hive to go all over his key and get theirs name and time stamp.
        :param reg: Regapi (volatility registry api)
        :return: None
        '''
        global reg_dict

        # This function need registryapi from volatility (one of registryapi is pycrypto)
        if not has_crypto:
            return

        # Add to job queue
        id = time.time()
        job_queue.put_alert((id, 'VolExp Search Registry Information ', 'Search for all the keys in each hive and order them in a tree', 'Running'))

        # Create regapi conf and start search for registry keys
        regapi_conf = conf.ConfObject()
        regapi_conf.readonly = {}
        regapi_conf.PROFILE = self._config.PROFILE
        regapi_conf.LOCATION = self._config.LOCATION
        regapi_conf.optparser.set_conflict_handler("resolve")
        regapi_conf.remove_option('ADDRESS')

        # Get volatility registry api
        reg = registryapi.RegistryApi(regapi_conf)
        print '[+] start REG_BULD'

        # Set the 'Finish build hives' key for the hives that done rune (support for cache file).
        if not reg_dict.has_key('Finish build hives'):
            reg_dict['Finish build hives'] = []

        # Go all over the hives offset and starts a thread to find all the keys in each hive.
        for offset in reg.all_offsets:
            #print reg.all_offsets[offset]

            # Reset the current reg hive and user
            reg.reset_current()

            # Find hive name
            hive_path = reg.all_offsets[offset].lower().replace('\\\\', '\\').split('\\')
            hive = hive_path[-1]

            # Check if this hive is well known and if so change his name (for user convenience).
            if KNOWN_HIVES.has_key(hive):
                hive = KNOWN_HIVES[hive]

            # Find user (if this is user hive).
            user = hive_path[4] if reg.all_offsets[offset].lower().find("\\" + "ntuser.dat") != -1 else None
            print '[+] start user {} \t hive:{}'.format(user, hive)

            # Start the thread to get all the keys (if this is not chached)
            if not hive in reg_dict['Finish build hives']:
                threading.Thread(target=self.reg_hive_thread_builder,args=(hive, user)).start()

        # Change the menu colore to default
        def change_menu_color():
            self.view_menu_bar.entryconfig(2, background=self.menu_bg)
            self.subview_menu_bar.entryconfig(0, background=self.menu_bg)
        queue.put((change_menu_color, ()))

        job_queue.put_alert((id, 'VolExp Search Registry Information ', 'Search for all the keys in each hive and order them in a tree', 'Done'))
        print '[+] done REG_BULD'

    def dump_reg(self):
        '''
        This function try to dump the registry using dumpregistry plugin
        :return: None
        '''
        threading.Thread(target=self.run_plugin_thread, args=('dumpregistry',)).start()

    def dump_certs(self):
        '''
        This function try to dump the certificates using dumpcerts plugin
        :return: None
        '''
        threading.Thread(target=self.run_plugin_thread, args=('dumpcerts',)).start()

    def dump_event_log(self):
        '''
        This function try to dump the registry using dumpfiles plugin
        :return: None
        '''
        threading.Thread(target=self.run_plugin_thread, args=('dumpfiles --regex=.evtx$ -i -n ',)).start()

    def run_plugin_thread(self, plugin_name):
        '''
        This function run sume plugin.
        :param plugin_name: the plugin to run
        :return: None
        '''
        global plugins_output

        print '[+] run {}'.format(plugin_name)

        # Get the dump dir
        dump_dir = urllib.url2pathname(volself._config.DUMP_DIR)

        if self.is_memtriage:
            command = r'"{}" "{}" --plugins={} -D "{}"'.format(sys.executable, self._vol_path, plugin_name, dump_dir)
        else:
            with lock:
                # Get the file path of the dump
                file_path = urllib.url2pathname(volself._config.location[7:])

                # Get the profile for this dump file
                profile = volself._config.PROFILE
            # take it to the thread function bellow and make it work, create gui
            command = r'"{}" "{}" --plugins="{}" -f "{}" --profile={} {} -D "{}"'.format(sys.executable, self._vol_path, all_plugins[0], file_path, profile,plugin_name, dump_dir)

        # Add to job queue
        id = time.time()
        job_queue.put_alert((id, 'Run Plugin', command, 'Running'))

        p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()

        # Wait for result
        p_status = p.wait()

        job_queue.put_alert((id, 'Run Plugin', command, 'Done'))
        print '[+] plugin_name:', plugin_name
        print output

    def run_plugin(self, plugin_name):
        '''
        This function run the cmdline plugin.
        :param plugin_name:
        :return:
        '''
        # Get the vol path
        vol_path = self._vol_path

        # Get the plugins directory
        plugins_path = all_plugins[0]

        # Set the file and profile to false (dont use it in memtriage).
        if self.is_memtriage:
            file_path = profile = False
        else:
            with lock:
                # Get the dump file path
                file_path = urllib.url2pathname(volself._config.location[7:])

                # Get the dump file profile
                profile = volself._config.PROFILE

        # Create and config the cmd like gui to run plugins using the CmdPlugin class.
        app = CmdPlugin(plugin_name, vol_path, plugins_path, file_path, profile)
        x = root.winfo_x()
        y = root.winfo_y()
        app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
        app.geometry("700x450")
        app.title('CmdPlugin')

    def change_style(self, style_index):
        """
        This function change the theme of the gui and colored the selected theme in the Menu
        :param style_index: the index inside the self.all_themes list
        :return: None
        """
        for index in range(len(self.all_themes)):

            # Set the theme if this is the currect theme used.
            if index == style_index:
                the_index = index

            else:
                self.style_menu.entryconfig(index, background=self.menu_bg)

        self.style_menu.entryconfig(the_index, background='LightBlue3')
        self.style.theme_use(self.all_themes[style_index])

        # For creating disable like treeview.
        disabled_bg = self.style.lookup("TEntry", "fieldbackground", ("disabled",))
        disabled_fg = self.style.lookup("TEntry", "foreground", ("disabled",))
        self.style.configure('blue.Horizontal.TProgressbar', background='blue')

        self.style.map("Treeview", fieldbackground=[("disabled", disabled_bg)], foreground=[("disabled", disabled_fg)])

    def spawn_vol(self, command):
        '''
        Spawn new cmd with volatility command
        :param command: the command for the cmd.
        :return: None
        '''
        file_path = urllib.url2pathname(volself._config.location[7:])
        profile = self._config.PROFILE
        start_vol(file_path, profile, command)

    #region controle+key event handles.
    def control_p(self, event):
        '''
        This function start a shell with no plugin
        :param event: evnet
        :return: None
        '''

        # Set plugin to nothing
        plugin_name = ''

        # Get the vol path
        vol_path = self._vol_path

        # Get the plugins directory
        plugins_path = all_plugins[0]

        # Get the dump file path
        file_path = urllib.url2pathname(volself._config.location[7:])

        # Get the dump file profile
        profile = volself._config.PROFILE

        # Create and config the cmd like gui to run plugins using the CmdPlugin class.
        app = CmdPlugin(plugin_name, vol_path, plugins_path, file_path, profile)
        x = root.winfo_x()
        y = root.winfo_y()
        app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
        app.geometry("700x450")
        app.title('CmdPlugin')

    def control_v(self, event):
        '''
        This function start shell with the parameters to start the new plugin.
        :param event: event
        :return: None
        '''
        self.spawn_vol('pslist')

    def control_h(self, event):
        '''
        This function popup the help menu
        :param event: event
        :return: None
        '''
        help = tk.Toplevel()
        HelpMe(help).pack(fill=BOTH, expand=YES)
        help.title("Help")
        help.geometry("1200x700")

    def s_control_h(self, event):
        '''
        This function add the help menu as a tab.
        :param event: event
        :return: None
        '''
        frame = HelpMe(self.NoteBook)
        self.NoteBook.add(frame, text="Help")

    def control_s(self, event):
        '''
        This function popup services screen.
        :param event: event
        :return: None
        '''

        # Show message and return if we don't Gather this information.
        if not has_crypto:
            messagebox.showerror('Error', 'You need to install pycrypto module to get this information (run in shell -> "pip install pycrypto")')
        elif service_dict == {}:
            messagebox.showwarning('Notice', 'Still searching for the information\nPlease try again later.')
        else:
            app = tk.Toplevel()
            x = root.winfo_x()
            y = root.winfo_y()
            app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
            ServicesAll(app).pack(fill=BOTH, expand=YES)
            app.title('Services')

    def s_control_s(self, event):
        '''
        This function add services as tab.
        :param event: event
        :return: None
        '''

        # Show message and return if we don't Gather this information.
        if not has_crypto:
            messagebox.showerror('Error', 'You need to install pycrypto module to get this information (run in shell -> "pip install pycrypto")')
        elif service_dict == {}:
            messagebox.showwarning('Notice', 'Still searching for the information\nPlease try again later.')
        else:
            data = []
            for pid in service_dict:
                data += service_dict[pid]
            frame = NBTab(self.NoteBook, jmp_pid_index=1, index_pid=3, headers=(
            'offset', 'order', 'start', 'pid', 'service name', 'display name', 'type', 'state', 'binary'), data=data,
                                       resize=False)
            self.NoteBook.add(frame, text='Services')

    def control_m(self, event):
        '''
        This function popup Mft Files explorer screen.
        :param event: event
        :return: None
        '''

        # Show message and return if we don't Gather this information.
        if mft_explorer == {}:
            messagebox.showwarning('Notice', 'Still searching for the information\nPlease try again later.')
        else:
            app = tk.Toplevel()
            x = root.winfo_x()
            y = root.winfo_y()
            app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
            Explorer(app, my_dict=mft_explorer ,headers=("File Name", "Creation", "Modified", "MFT alerted", "Access", "Use", "Type", "Link count", "Record number", "Offset"), searchTitle='Search Form MFT Records', resize=False, relate=app).pack(fill=BOTH, expand=YES)
            app.title("MFT Files Explorer")

    def s_control_m(self, event):
        '''
        This function add Mft Files explorer as tab.
        :param event: event
        :return: None
        '''

        # Show message and return if we don't Gather this information.
        if mft_explorer == {}:
            messagebox.showwarning('Notice', 'Still searching for the information\nPlease try again later.')
        else:
            frame = Explorer(self.NoteBook, my_dict=mft_explorer ,headers=("File Name", "Creation", "Modified", "MFT alerted", "Access", "Use", "Type", "Link count", "Record number", "Offset"), searchTitle='Search Form MFT Records', relate=root)
            self.NoteBook.add(frame, text="MFT Files Explorer")

    def control_w(self, event):
        '''
        This function popup WinObj Explorer screen.
        :param event: event
        :return: None
        '''

        # Show message and return if we don't Gather this information.
        if not has_winobj:
            messagebox.showerror('Error', 'Please download winobj.py to see this information (github: kslgroup)')
        elif winobj_dict == {}:
            messagebox.showwarning('Notice', 'Still searching for the information\nPlease try again later.')
        else:
            app = tk.Toplevel()
            x = root.winfo_x()
            y = root.winfo_y()
            app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
            WinObjExplorer(app, winobj_dict, resize=False, relate=app).pack(fill=BOTH, expand=YES)
            app.title("WinObj Explorer(Shachaf Atun[KslGroup])")
            x = root.winfo_x()
            y = root.winfo_y()
            app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
            app.geometry("700x450")

    def s_control_w(self, event):
        '''
        This function add WinObj Explorer screen as a tab.
        :param event: event
        :return: None
        '''

        # Show message and return if we don't Gather this information.
        if not has_winobj:
            messagebox.showerror('Error', 'Please download winobj.py to see this information (github: kslgroup)')
        elif winobj_dict == {}:
            messagebox.showwarning('Notice', 'Still searching for the information\nPlease try again later.')
        else:
            frame = WinObjExplorer(self.NoteBook, winobj_dict, resize=False, relate=root)
            self.NoteBook.add(frame, text="WinObj Explorer")

    def control_e(self, event):
        '''
        This function popup Files Explorer screen.
        :param event: event
        :return: None
        '''

        # Show message and return if we don't Gather this information.
        if files_scan == {}:
            messagebox.showwarning('Notice', 'Still searching for the information\nPlease try again later.')
        else:
            app = tk.Toplevel()
            x = root.winfo_x()
            y = root.winfo_y()
            app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
            FileExplorer(app, dict=files_scan, headers=("File Name", "Access", "Type", "Pointer Count", "Handle Count", "Offset"), searchTitle='Search For Files', relate=app).pack(fill=BOTH, expand=YES)
            app.title("Files Explorer")
            app.geometry("1400x650")

    def s_control_e(self, event):
        '''
        This function add Files Explorer as a tab.
        :param event: event
        :return: None
        '''

        # Show message and return if we don't Gather this information.
        if files_scan == {}:
            messagebox.showwarning('Notice', 'Still searching for the information\nPlease try again later.')
        else:
            frame = FileExplorer(self.NoteBook, dict=files_scan, headers=("File Name", "Access", "Type", "Pointer Count", "Handle Count", "Offset"), searchTitle='Search For Files', resize=False, relate=root)
            self.NoteBook.add(frame, text="Files Explorer")

    def control_r(self, event):
        '''
        This function popup Registry viewer screen.
        :param event: event
        :return: None
        '''

        # Show message and return if we don't Gather this information.
        if not has_crypto:
            messagebox.showerror('Error', 'You need to install pycrypto module to get this information (run in shell -> "pip install pycrypto")')
        elif reg_dict == {}:
            messagebox.showwarning('Notice', 'Still searching for the information\nPlease try again later.')
        else:
            def create_reg_viewer(self):

                def create_the_gui(regapi):
                    app = tk.Toplevel()
                    x = root.winfo_x()
                    y = root.winfo_y()
                    app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
                    RegViewer(app, dict=reg_dict, headers=("Key Name", "Creation"), reg_api=regapi).pack(fill=BOTH, expand=YES)
                    # app = Explorer(my_dict=reg_dict, headers=('reg', 'time'))
                    app.title("RegEdit")
                    app.geometry("800x500")

                # Create the config
                regapi_conf = conf.ConfObject()
                regapi_conf.readonly = {}
                regapi_conf.PROFILE = self._config.PROFILE
                regapi_conf.LOCATION = self._config.LOCATION
                regapi_conf.remove_option('ADDRESS')
                regapi = registryapi.RegistryApi(regapi_conf)
                queue.put((create_the_gui, (regapi,)))

            threading.Thread(target=create_reg_viewer, args=(self,)).start()

    def s_control_r(self, event):
        '''
        This function add Registry Viewer as a tab.
        :param event: event
        :return: None
        '''

        # Show message and return if we don't Gather this information.
        if not has_crypto:
            messagebox.showerror('Error', 'You need to install pycrypto module to get this information (run in shell -> "pip install pycrypto")')
        elif reg_dict == {}:
            messagebox.showwarning('Notice', 'Still searching for the information\nPlease try again later.')
        else:
            def create_reg_viewer(self):

                def create_the_gui(regapi):
                    frame = RegViewer(self.NoteBook, dict=reg_dict, headers=("Key Name", "Creation"), reg_api=regapi)
                    self.NoteBook.add(frame, text="RegViewer")

                regapi_conf = conf.ConfObject()
                regapi_conf.readonly = {}
                regapi_conf.PROFILE = self._config.PROFILE
                regapi_conf.LOCATION = self._config.LOCATION
                regapi_conf.remove_option('ADDRESS')
                regapi = registryapi.RegistryApi(regapi_conf)
                queue.put((create_the_gui, (regapi,)))

            threading.Thread(target=create_reg_viewer, args=(self,)).start()

    def control_t(self, event):
        '''
        This Function return the tree view to the start view
        :param event: event
        :return: None
        '''
        main_table.show_process_tree()

    def s_control_t(self, event):
        '''
        This function add another process tree to screen as a tab.
        :param event: event
        :return: None
        '''

        # Show message and return if we don't Gather this information.
        pw = PanedWindow(self.NoteBook, orient='vertical')
        headers = (
        'Process', 'PID', 'PPID', 'CPU (%)', 'Private Bytes (KB)', 'Working Set (KB)', 'Description', 'Company Name',
        'DEP', 'ASLR', 'CFG', 'Protected', 'Debugger Present', 'Prefetch', 'Threads', 'Handles', 'User Name', 'Session',
        'Heap Count', 'Stack Count', 'PageFault Count', 'Desktop', 'Image Type', 'Context Switch', 'Windows Status','integrity', 'Priority',
        'CPU Time', 'Cycles', 'Private Working Set (KB)', 'Peak Private Byte (KB)', 'Peak Working Set (KB)', 'Virtual Size (KB)', 'Peak Virtual Size (KB)',
        'Created Time', 'Internal Name', 'Original File Name', 'Windows Title', 'Command Line', 'Path', 'Current Directory', 'Version', 'Address')
        treetable = ProcessesTable(pw, headers=headers, data=self.list_all, text_by_item=1, resize=True,
                                   display=headers[1:6])
        treetable.pack(side=TOP, fill=BOTH)
        pw.add(treetable)
        pw.pack(fill=BOTH, expand=YES)
        self.NoteBook.add(pw, text='Processes')

    def s_control_d(self, event):
        '''
        This function add the drivers to screen as a tab.
        :param event: event
        :return: None
        '''

        # Show message and return if we don't Gather this information.
        if process_dlls.has_key(4):
            modev_data = [(item[item.rfind('\\')+1:], item) + ((process_bases[4]['dlls'][item[item.rfind('\\')+1:]], process_bases[4]['ldr'][item[item.rfind('\\')+1:]]) if process_bases[4]['dlls'].has_key(item[item.rfind('\\')+1:]) else (-1, -1)) for item in process_dlls[4]]
            modules_table = Modules(self.NoteBook, jmp_pid_index=1, jmp_pid=4,
                                       headers=("Name", "Path", "Dll Base", "LDR Address"),
                                       data=modev_data, resize=True)
            modules_table.pack(side=TOP, fill=BOTH)
            self.NoteBook.add(modules_table, text='Modules')
        else:
            messagebox.showwarning('Notice', 'Still searching for the information\nPlease try again later.')

    def s_control_n(self, event):
        '''
        This function add connection information to screen as a tab.
        :param event: event
        :return: None
        '''

        if process_connections == {}:
            messagebox.showwarning('Notice', 'Still searching for the information\nPlease try again later.')
        else:
            data = []
            for proc in process_connections:
                data += process_connections[proc]
            network_table = NBTab(self.NoteBook, jmp_pid_index=1, index_pid=0,
                                       headers=(
                                       "Pid", "Protocol", "Local Address", "Remote Address", "State", "Created", "Offset"),
                                       data=data, resize=True)
            network_table.pack(side=TOP, fill=BOTH)
            self.NoteBook.add(network_table, text='Network')

    def properties(self, event=None):
        '''
        This function popup the process properties as a seperate tab.
        :param event: event
        :return: None
        '''
        self.treetable.OnDoubleClick(None)

    def s_properties(self, event):
        '''
        This function add the process properties to the main tab
        :param event:
        :return:
        '''
        self.treetable.OnDoubleClick(None, top_level=False)

    def control_i(self, event):
        '''
        This function popup Memory information.
        :param event: event
        :return: None
        '''

        # Show message and return if we don't Gather this information.
        if pfn_stuff == {}:
            messagebox.showwarning('Notice', 'Still searching for the information\nPlease try again later.')
        else:
            app = memInfo()
            x = root.winfo_x()
            y = root.winfo_y()
            app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
            app.title('Memory Information:')
            app.geometry("300x500")
            for thread in self.threads:
                if thread.name == "pfn_stuff" and thread.is_alive():
                    messagebox.showwarning('Notice', 'Still searching for the information\nThe information displayed here will update next time you enter this window\nPlease try again later.')

    def view_comments(self, event=None):
        ''' Create the view comments gui '''

        # Init variables.
        app = tk.Toplevel()
        x = root.winfo_x()
        y = root.winfo_y()
        app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
        app.geometry("900x620")
        app.title('User Comments')
        label = ttk.Label(app, text="Here you can get information about all of your comments.")
        label.pack(side="top", fill="x", pady=10)
        pw = PanedWindow(app, orient='vertical')
        process_headers = ('Process Pid', 'Process Comment')
        process_data = []
        files_headers = ('Process Pid', 'PE Path', 'PE Comment')
        files_data = []

        # Go all over the pids.
        for pid in process_dlls:

            # Get the processes comment (if this is not the default).
            if not (process_comments[pid] == "Write Your Comments Here." or (process_comments[pid].startswith("Write Your Comments Here.") and process_comments[pid].endswith(")."))):
                process_data.append((pid, process_comments[pid]))
                first = True
                for line in process_comments[pid].splitlines():
                    if first:
                        first = False
                        continue
                    process_data.append((pid, line))

            # Go all over the files inside each process.
            for path in pe_comments['pid'][pid]:

                # Get the file comment (if this is not the default).
                if pe_comments['pid'][pid][path][0] != "Write Your Comments Here.":
                    files_data.append((pid, path, pe_comments['pid'][pid][path]))
                    first = True
                    for line in pe_comments[pid][path][0].splitlines():
                        if first:
                            first = False
                            continue
                        files_data.append((pid, line))

        # Pack the tables.
        process_treetable = TreeTable(pw, headers=process_headers, data=process_data)
        process_treetable.tree['height'] = 12 if 12 < len(process_data) else len(process_data)
        process_treetable.pack(expand=YES, fill=BOTH)
        pw.add(process_treetable)
        files_treetable = TreeTable(pw, headers=files_headers, data=files_data)
        files_treetable.tree['height'] = 12 if 12 < len(files_data) else len(files_data)
        files_treetable.pack(expand=YES, fill=BOTH)
        pw.add(files_treetable)
        pw.pack(expand=YES, fill=BOTH)

    # endregion controle+key event handles.

    def about(self, event=None):
        '''
        This function spawn the about top level.
        :param event: event
        :return: None
        '''
        About(self.img)

    def update_table_all(self):
        '''
        Searching for some data while the gui is running
        The data that searched here will also update the gui main table in the end of the funciton.
        data searched: files information (for process and modules), usernames.
        :return: None
        '''
        global main_table
        global files_info
        global process_tree_data
        global done_run
        global queue
        global user_sids
        global lock

        # Return if the user don't have pycrypto install
        if not has_crypto:
            return

        # Get the files_info only if we dont have it already (run from saved .atz file)
        if not files_info.has_key('/done/') or not files_info['/done/']:

            # Get files info
            self.get_proc_verinfo()
            files_info['/done/'] = True

        # Get user sids and conf object
        get_sids_class_conf = conf.ConfObject()
        get_sids_class_conf.readonly = {}
        get_sids_class_conf.PROFILE = self._config.PROFILE
        get_sids_class_conf.LOCATION = self._config.LOCATION
        get_sids_class_conf.optparser.set_conflict_handler("resolve")
        get_sids_class = getsids.GetSIDs(get_sids_class_conf)
        user_sids = get_sids_class.lookup_user_sids()
        done_run['user_sids'] = user_sids

        def main_table_update(user_sids):
            """
            This function update the main table items with the new data
            :return: None
            """
            global tree_view_data
            global files_info
            global process_security
            global lock

            # Token security attributes:
            """
            #define SE_GROUP_MANDATORY                 (0x00000001L)
            #define SE_GROUP_ENABLED_BY_DEFAULT        (0x00000002L)
            #define SE_GROUP_ENABLED                   (0x00000004L)
            #define SE_GROUP_OWNER                     (0x00000008L)
            #define SE_GROUP_USE_FOR_DENY_ONLY         (0x00000010L)
            #define SE_GROUP_INTEGRITY                 (0x00000020L)
            #define SE_GROUP_INTEGRITY_ENABLED         (0x00000040L)
            #define SE_GROUP_LOGON_ID                  (0xC0000000L)
            #define SE_GROUP_RESOURCE                  (0x20000000L)
            """
            token_security_attributes = {0: 'Attached (process user name)', 7: 'Mandatory', 10: 'Owner', 14: 'Owner',
                                         16: 'Deny', 96: 'Integrity'}

            # Add new privilege to the privilege dictionary (for windows 10).
            privileges.PRIVILEGE_INFO[36] = ("SeDelegateSessionUserImpersonatePrivilege",
                                             "Obtain an impersonation token for another user in the same session.")

            rows = main_table.get_all_children(main_table.tree, "", False)
            main_table.show_process_tree()

            # Go all over the rows in the main table row is a tuple(row_id, row_parent_id)
            for row in rows:
                #tree_view_data[count] = row

                # we need now only the row id
                row = row[0]

                # Get all the data from the main table
                process, pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc = main_table.tree.item(row)['values']

                # Get the EPROCESS struct.
                e_proc = obj.Object('_EPROCESS', e_proc, self.kaddr_space)

                # Update the users information (only if has pycrypto install)
                if has_crypto:
                    # Create process_security[pid] if not exists
                    if not process_security.has_key(int(pid)):
                        process_security[int(pid)] = {}

                    # Empty/Create the process_security[pid]['Groups'] (the process group security).
                    # process_security[int(pid)]['Groups'] = [] # (overid the list[index] instead)

                    # Get the token
                    token = e_proc.get_token()
                    sid_count = 0

                    # If token valid.
                    if token and token.is_valid():
                        first_sid_name = True
                        sid_name = "Unable To Find"

                        # Go all over the sids for this token and insert them the right user name (that we get from searching
                        # in the registry using GetSIDs plugin)
                        for sid_string in token.get_sids():
                            update_security = True

                            # Get a name for this sid
                            if sid_string in getsids.well_known_sids:
                                sid_name = str(getsids.well_known_sids[sid_string])
                            elif sid_string in getsids.getservicesids.servicesids:
                                sid_name = str(getsids.getservicesids.servicesids[sid_string])
                            elif sid_string in user_sids:
                                sid_name = str(user_sids[sid_string])
                            else:
                                sid_name_re = getsids.find_sid_re(sid_string, getsids.well_known_sid_re)
                                if sid_name_re:
                                    sid_name = str(sid_name_re)
                                else:
                                    sid_name = ""

                            c_index = 0
                            for tup in process_security[int(pid)]['Groups']:
                                if sid_string == tup[1]:
                                    break

                                c_index += 1
                            else:
                                proc_token_sid_array = token.UserAndGroups.dereference()
                                attr = proc_token_sid_array[sid_count].Attributes
                                if attr > 9999:
                                    sid_flag = 'Logon ID'
                                else:
                                    for sid_secure in token_security_attributes:
                                        if int(attr) == sid_secure:
                                            sid_flag = token_security_attributes[
                                                sid_secure] if sid_secure in token_security_attributes else str(
                                                sid_secure)
                                            break
                                    else:
                                        sid_flag = 'Unsupported ({})'.format(attr)
                                update_security = False
                                process_security[int(pid)]['Groups'].append((sid_name, sid_string, sid_flag))

                            # Update the process_security (if we didnt add one).
                            if update_security:
                                process_security[int(pid)]['Groups'][c_index] = ((sid_name, sid_string, process_security[int(pid)]['Groups'][c_index][2]))

                            if first_sid_name:
                                first_sid_name = False
                                un = sid_name

                            sid_count += 1

                    # Set  the user name if we didnt find it yet (if this still Searching...)
                    un = "Unable To Find" if un == "Searching..." else un


                # Get file information from verinfo
                path = e_proc.Peb.ProcessParameters.ImagePathName

                # Check if we have information of this process file (we probably get this information in the
                # self.get_proc_verinfo function)
                if files_info.has_key(str(path).lower()):

                    # Get the company name of this file
                    if files_info[str(path).lower()].has_key("CompanyName"):
                        cn = files_info[str(path).lower()]["CompanyName"]

                    # Get the description of this file
                    if files_info[str(path).lower()].has_key("FileDescription"):
                        Description = files_info[str(path).lower()]["FileDescription"]

                    # Get the version of this file
                    if files_info[str(path).lower()].has_key("FileVersion"):
                        version = files_info[str(path).lower()]["FileVersion"]

                    # Get the internal name for this file
                    if files_info[str(path).lower()].has_key("InternalName"):
                        intName = files_info[str(path).lower()]["InternalName"]

                    # Get the original file name of this file
                    if files_info[str(path).lower()].has_key("OriginalFilename"):
                        ofn = files_info[str(path).lower()]["OriginalFilename"]

                # Update the table (and the visual table)
                main_table.tree.item(row, values=(process, pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc))
                main_table.visual_drag.item(row, values=(process, pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc))

                count = 0
                # Update the new list
                for found_item in self.list_all:
                    if int(found_item[1]) == pid:
                        break
                    count += 1

                self.list_all[count] = ([str(this_item) for this_item in [self.list_all[count][0], pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc]])

                # if len(process_tree_data) > count:
                process_tree_data[count] = ([str(this_item) for this_item in [self.list_all[count][0], pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc]])

            # If the user didn't change the default display then append to this display the company name and file description
            self.treetable.tree["displaycolumns"] = self.treetable.headers[1:8] if self.treetable.tree["displaycolumns"] == self.treetable.headers[1:6] else self.treetable.tree["displaycolumns"]

            # Update the tree_view_data
            tree_view_data = [(main_table.tree.set(child[0], 'Process'), child)
                    for child in main_table.get_all_children(main_table.tree)]

            # Update done_run
            done_run['process_security'] = process_security

            lock.release()

        lock.acquire()

        # Send a message to the user that the gui will stop working for couple of seconds
        queue.put((messagebox.showinfo, ("Please Wait!", "The GUI will be unavailable for a couple of seconds..\nUpdating all files and user information in the main table (you can view them using select column [ctrl+c])\nNow we will start creating the Registry Explorer(view using view - > Registry Explorer the items will update at runtime)")))

        # display a messagepopup to the user that the gui will stop working for couple of seconds
        queue.put((MessagePopUp, ('The GUI will be unavailable for a couple of seconds..\nUpdating all files and user information in the main table (you can view them using select column [ctrl+c])\nNow we will start creating the Registry Explorer(view using view - > Registry Explorer the items will update at runtime)',5 , root, "Please Wait!")))

        # Call the update function (will stop the gui for a cuple of seconds).
        queue.put((main_table_update, (user_sids,)))

        # Start running the registry searching Thread
        t8 = threading.Thread(target=self.registry_keys, name='registry_keys')
        t8.daemon = True
        self.threads.append(t8)

        # Wait for update table all to finish before start.
        with lock:
            t8.start()

    def disassemble(self, proc_addr_space, address, size=128):
        '''
        Dissasmble of specific address in specific address space (default size=128)
        return: (hex_dump, disassmble)
        '''

        # Set the variables
        address = int(address)
        size = int(size)

        # Read the memory from the process address space
        mem = proc_addr_space.read(address, size)

        # If we get any valid data.
        if mem:

            # Get hexdump data
            hex_dump = ("{0}".format("\n".join(
                    ["{0:#010x}  {1:<48}  {2}".format(address + o, h, ''.join(c))
                     for o, h, c in utils.Hexdump(mem)])))

            # If we have distorm3 then get disassmbly as well
            if has_distorm:
                bits = proc_addr_space.profile.metadata.get('memory_model')
                if bits == '32bit':
                    bits = distorm3.Decode32Bits
                else:
                    bits = distorm3.Decode64Bits

                dis_text = "\n".join(["{0:<#010x} {1:<18} {2}".format(o, h, i) \
                                              for o, _size, i, h in \
                                              distorm3.DecodeGenerator(address, mem, bits)])
            else:
                dis_text = "Please Installl Distorm3"
            return (hex_dump, dis_text)
        return ("Failed To read addr space", "or Memory paged out")

    def save(self, location=None):
        """
        Summon the save_thread (so the gui does not stuck)
        """
        # If not canceled.
        if location != '':
            MessagePopUp(
                'Saving your data to a file\nIt will take a couple of seconds\nA message will display when it\'s over', 5, root)
            threading.Thread(target=self.save_thread, args=(location,)).start()

    def save_thread(self, location_path=None):
        """
        Save all the plugin info to display (save all of this as a cache).
        """
        global done_run, save_file_name
        global location, dump_dir, profile, api_key, vol_path


        for key in done_run:
            if (not done_run[key]) and key in globals() and len(globals()[key]) > 0:
                done_run[key] = globals()[key]
        saved_data = {}

        for dict_name in done_run:
            #print str(dict_name)
            if done_run[dict_name]:
                # The process_bases object and we didnt change the format before.
                if dict_name == 'process_bases' and not type(done_run[dict_name][4]['proc']) is str:
                    new_dic = {}
                    for pid in done_run[dict_name]:
                        new_dic[pid] = {"proc":None, "dlls":{}}
                        new_dic[pid]["dlls"] = dict(process_bases[pid]['dlls'])
                        new_dic[pid]["proc"] = str(process_bases[pid]['proc'].v()).strip('L')
                        new_dic[pid]["ldr"] = dict(process_bases[pid]['dlls'])
                        done_run[dict_name] = new_dic

                saved_data[dict_name] = done_run[dict_name]

        file_name = save_file_name = save_file_name or os.path.join(location_path or self._config.DUMP_DIR, r'volexp_{}.atz'.format(time.time()))
        saved_data['vol_path'] = vol_path
        saved_data['location'] = location
        saved_data['dump_dir'] = dump_dir
        saved_data['profile'] = profile
        saved_data['api_key'] = api_key
        saved_data['save_file_name'] = save_file_name
        saved_data['pfn_stuff'] = pfn_stuff
        saved_data['pe_comments'] = pe_comments

        # Dump the data to a file.
        with open(file_name, 'wb') as handle:
            pickle.dump(saved_data, handle, protocol=pickle.HIGHEST_PROTOCOL)
        print '[+] Done create saved file:{}'.format(file_name)

        queue.put((messagebox.showinfo, ("Done create saved file:", file_name)))

    def load(self, file_path):
        """
        load all the plugin info(that saved before[sould be call after __init__])
        dict{'files_info':files_info}
        """
        global files_info, process_dlls, process_handles, process_bases, process_threads, process_connections, process_imports, process_env_var, process_security, process_performance, process_comments, tree_view_data, pfn_stuff, mft_explorer, files_scan, winobj_dict, reg_dict, service_dict, all_plugins, process_tree_data, pfn_stuff, pe_comments, user_sids
        global location, dump_dir, profile, api_key, vol_path, save_file_name
        global done_run

        # Open the saved file
        with open(file_path, 'rb') as handle:
            saved_data = pickle.load(handle)

        # Configure default arguments
        location = saved_data['location']
        dump_dir = saved_data['dump_dir']
        profile = saved_data['profile']
        api_key = saved_data['api_key']
        vol_path = saved_data['vol_path']
        save_file_name = saved_data['save_file_name']
        self._config.LOCATION = location
        self._config.PROFILE = profile
        self.kaddr_space = utils.load_as(self._config)

        print '[+] loaded:', location, dump_dir, profile, api_key, vol_path

        # Go all over the saved data and insert them to the globals() and done_run
        globals().update(saved_data)
        done_run.update(saved_data)

        # Yield all the process data
        for task_data in process_tree_data:
            process, pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc = task_data
            process_bases[int(pid)]['proc'] = obj.Object('_EPROCESS', int(e_proc), self.kaddr_space) if e_proc else ''
            yield process, pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc

    def memtriage_update(self):
        '''
        Update all the data on real time
        :return: None
        '''

        global process_dlls
        global process_comments
        global process_bases
        global process_tree_data
        global process_performance
        global process_token
        global pe_comments
        global process_threads
        global process_security

        print '[+] start memtriage update (BETA, unstable)'

        updating_pid = -1
        process_name = -1
        new_list_all   = []
        process_counter = 0
        my_memtriage_conf = conf.ConfObject()
        my_memtriage_conf.readonly = {}
        my_memtriage_conf.PROFILE = self._config.PROFILE
        my_memtriage_conf.LOCATION = self._config.LOCATION
        my_memtriage_conf.KDBG = self._config.KDBG
        memtriage_kaddr_space = utils.load_as(my_memtriage_conf)
        current_ps_list = list(tasks.pslist(memtriage_kaddr_space))


        # https://docs.microsoft.com/en-us/previous-versions/dotnet/articles/bb625963(v=msdn.10)?redirectedfrom=MSDN
        #                  low            medium        high             system
        integrity_sids = ["S-1-16-4096", "S-1-16-8192", "S-1-16-12288", "S-1-16-16384"]
        integrity_levels = ["Untrusted", "Low", "Medium", "High", "System"]

        # default_user_integrity = {"LocalSystem": "System", "LocalService": "System", "NetworkService": "System", "Administrators": "High", "Backup Operators": "High", "Network Configuration Operators": "High", "Cryptographic Operators": "High", "Authenticated Users": "Medium", "Everyone": "Low", "Anonymous": "Untrusted"}
        """
        00 S-1-5-21-1712426984-1618080182-1209977580-513 Attributes - Mandatory Default Enabled
        01 S-1-1-0 Attributes - Mandatory Default Enabled
        02 S-1-5-32-544 Attributes - Mandatory Default Enabled Owner
        03 S-1-5-32-545 Attributes - Mandatory Default Enabled
        04 S-1-5-2 Attributes - Mandatory Default Enabled
        05 S-1-5-11 Attributes - Mandatory Default Enabled
        06 S-1-5-21-1712426984-1618080182-1209977580-1110 Attributes - Mandatory Default Enabled
        """

        # process protection:
        """ Process protection siner levels (the dozen from the hexa value in the dict)
        Signer      level         description
        WinSystem     7           System and minimal process
        WinTcp        6           Critical Windows components PROCESS_TERMINATE is unavailable.
        Windows       5           Important Windows Components handling sensitive data
        LSA           4           Lsass.exe (if configured to run protected).
        Antimalware   3           Antimalware service processes, including 3rd party, PROCESS_TERMINATE is unavailable.
        CodeGen       2           .NET native code generation.
        Authenticode  1           Hosting DRM content.
        None          0           Process is not protected.
        """
        protect_signer_by_level = {0x72: 'System Level Protection', 0x62: 'PsProtectedSignerWinTcb',
                                   0x61: 'PsProtectedSignerWinTcb-Light', 0x52: 'PsProtectedSignerWindows',
                                   0x51: 'PsProtectedSignerWindows-Light', 0x41: 'PsProtectedSignerLsa-Light',
                                   0x31: 'PsProtectedSignerAntimalware-Light', 0x21: 'PsProtectedSignerAuthenCode',
                                   0x11: 'PsProtectedSignerAuthenCode-Light'}

        # Token security attributes:
        """
        #define SE_GROUP_MANDATORY                 (0x00000001L)
        #define SE_GROUP_ENABLED_BY_DEFAULT        (0x00000002L)
        #define SE_GROUP_ENABLED                   (0x00000004L)
        #define SE_GROUP_OWNER                     (0x00000008L)
        #define SE_GROUP_USE_FOR_DENY_ONLY         (0x00000010L)
        #define SE_GROUP_INTEGRITY                 (0x00000020L)
        #define SE_GROUP_INTEGRITY_ENABLED         (0x00000040L)
        #define SE_GROUP_LOGON_ID                  (0xC0000000L)
        #define SE_GROUP_RESOURCE                  (0x20000000L)
        """
        token_security_attributes = {0: 'Attached (process user name)', 7: 'Mandatory', 10: 'Owner', 14: 'Owner',
                                     16: 'Deny', 96: 'Integrity'}

        # Add new privilege to the privilege dictionary (for windows 10).
        privileges.PRIVILEGE_INFO[36] = ("SeDelegateSessionUserImpersonatePrivilege",
                                         "Obtain an impersonation token for another user in the same session.")

        # Thread flags mask
        thread_flags = {0: "Terminate", 1: "Dead", 2: "Hide from debug", 3: "Impersonating", 4: "System",
                        5: "Hard Error Disable", 6: "Break On Termination", 7: "Skip Creation Message",
                        8: "Skip Terminate Message"}

        # This function finds the number of parents for this process.
        def find_number_of_parents(e_proc):
            '''
            This function find the number of parent (that present in the ps_list).
            :param e_proc: the _EPROCESS struct of the process we want to find the number of parents
            :return: int - number of parents
            '''
            number_of_parents = 0
            while True:
                for proc in current_ps_list:

                    # If this is the parent process by id and created time.
                    if int(proc.UniqueProcessId) == int(e_proc.InheritedFromUniqueProcessId) and proc.CreateTime <= e_proc.CreateTime:
                        number_of_parents += 1
                        e_proc = proc
                        break
                else:
                    return number_of_parents

        def find_index_of_proc_ppid_in_list(list, proc_data):
            '''
            This function find the index where to insert the new process that found,
            (in the buttom of the parent process childs).
            :param list: the list of all the data.
            :param proc_data: the data of the process
            :return: int - the index
            '''
            index = 0
            after_proc = False
            for data in list:

                # If pid  == ppid (of the searched process)
                if data[1] == proc_data[2]:
                    #return index
                    after_proc = True

                # After all the parent process child (so we get the last index)
                elif after_proc and data[1] != proc_data[2]:
                    return index
                index += 1

            # Return the last index of the list if no item found (unable to find parent process).
            return len(list)


        # Go all over the process tree # Image Type, Context Switch, Windows Status,
        for current_e_proc in current_ps_list:#proc_T in self.return_pstree():
            process, pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc = [
                str(i - i - 1) for i in range(43)]
            e_proc = current_e_proc
            updating_pid = pid = int(e_proc.UniqueProcessId)
            ppid = int(e_proc.InheritedFromUniqueProcessId)
            proc_token = e_proc.get_token()

            # Create the process_dlls and proc_bases
            if not process_comments.has_key(int(pid)):
                process_comments[int(pid)] = "Write Your Comments Here."
                pe_comments['pid'][int(pid)] = {}

                # Create dict inside the process_threads[pid]
                process_threads[int(pid)] = {}
            process_bases[int(pid)] = {"proc": e_proc, "dlls": {}}
            process_bases[int(pid)]["dlls"] = {}
            process_bases[int(pid)]["ldr"] = {}
            process_dlls[int(pid)] = []

            # Create a dictionary inside the process_security[pid] if not exists.
            if not process_security.has_key(int(pid)):
                process_security[int(pid)] = {}

            # Create a list inside the process_security[pid]['Privs']
            #if not process_security[int(e_proc.UniqueProcessId)].has_key('Privs'):
            process_security[int(pid)]['Privs'] = []

            # Add the session to the process_security[pid]['session']
            process_security[int(pid)]['session'] = int(e_proc.ProcessInSession)


            # This item update lated (on update_table_all)
            un, cn, Description, version, intName, ofn = " ", " ", " ", " ", " ", " "

            threads = e_proc.ActiveThreads
            handles = e_proc.ObjectTable.HandleCount if e_proc.ObjectTable.HandleCount else -1 if not process_handles.has_key(
                int(pid)) else len(process_handles[int(pid)])

            # add token info
            token_user = "{}\{}".format(str(get_right_member(proc_token, ['LogonSession.AuthorityName'])),
                                        str(get_right_member(proc_token, ['LogonSession.AccountName'])))
            token_session = str(get_right_member(proc_token, ['LogonSession.LogonId.LowPart']))  # int()
            token_session_id = str(get_right_member(proc_token, ['SessionId']))
            token_elevated = ""
            token_virtualized = ""
            token_protected = ""
            process_token[int(pid)] = (
            str(proc_token.v()), token_user, token_session, token_session_id, token_elevated, token_virtualized,
            token_protected)
            #

            integrity = int(get_right_member(proc_token, ["IntegrityLevelIndex"]) or -1)
            integrity = "{} (Token)".format(integrity_levels[int(proc_token.IntegrityLevelIndex)] if int(
                get_right_member(proc_token, ["IntegrityLevelIndex"]) or 99) < len(integrity_levels) else integrity)

            if not process_security[int(pid)].has_key('Groups'):
                process_security[int(pid)]['Groups'] = []
            un = "Searching..."
            first_sid_name = True
            proc_token_sid_array = proc_token.UserAndGroups.dereference()
            sid_count = 0
            changed_groups_index = []
            for sid_string in proc_token.get_sids():

                # Getting the attribute flag
                attr = proc_token_sid_array[sid_count].Attributes
                sid_count += 1

                sid_flag = attr

                if attr > 9999:
                    sid_flag = 'Logon ID'
                else:
                    for sid_secure in token_security_attributes:
                        if int(attr) == sid_secure:
                            sid_flag = token_security_attributes[
                                sid_secure] if sid_secure in token_security_attributes else str(sid_secure)
                            break
                    else:
                        sid_flag = 'Unsupported ({})'.format(attr)

                # Getting the sid string
                if done_run.has_key('user_sids'):
                    sid_name = 'Unable To Find'
                else:
                    sid_name = "Searching..."

                if has_crypto:
                    if sid_string in getsids.well_known_sids:
                        sid_name = str(getsids.well_known_sids[sid_string])
                    elif sid_string in getsids.getservicesids.servicesids:
                        sid_name = str(getsids.getservicesids.servicesids[sid_string])
                    elif sid_string in user_sids:
                        sid_name = str(user_sids[sid_string])
                    else:
                        sid_name_re = getsids.find_sid_re(sid_string, getsids.well_known_sid_re)
                        if sid_name_re:
                            sid_name = str(sid_name_re)
                        else:
                            sid_name = ""

                if sid_string in integrity_sids:
                    integrity = "{} (SID)".format(integrity_levels[1:][integrity_sids.index(sid_string)])

                # The first sid display is the username
                if first_sid_name:
                    first_sid_name = False
                    un = sid_name

                # Check if the sid is in there.
                for my_current_counter in range(len(process_security[int(pid)]['Groups'])):
                    item1, item2, item3 = process_security[int(pid)]['Groups'][my_current_counter]
                    if item2 == sid_string:
                        changed_groups_index.append(my_current_counter)
                        process_security[int(pid)]['Groups'][my_current_counter] = (sid_name if sid_name != "Searching..." or sid_string != item2 else item1, sid_string, sid_flag)
                        break
                else:
                    changed_groups_index.append(len(process_security[int(pid)]['Groups']))
                    process_security[int(pid)]['Groups'].append((sid_name, sid_string, sid_flag))

            # Remove removed groups from process_security
            if len(changed_groups_index) > len(process_security[int(pid)]['Groups']):
                removed_groups = []
                for index in range(len(process_security[int(pid)]['Groups'])):
                    if not index in changed_groups_index:
                        removed_groups.append(process_security[int(pid)]['Groups'][index])

                for c_group in removed_groups:
                    process_security[int(pid)]['Groups'].remove(c_group)

            # Go all over the privileges inside the process token.
            for value, present, enabled, default in proc_token.privileges():
                # Skip privileges whose bit positions cannot be
                # translated to a privilege name
                try:
                    name, desc = privileges.PRIVILEGE_INFO[int(value)]
                except KeyError:
                    continue

                # Set the attributes
                attributes = []
                if present:
                    attributes.append("Present")
                if default:
                    attributes.append("Default")
                if enabled:
                    attributes.append("Enabled")

                if attributes != []:

                    # By default privs are disable (we need to enable them to use them).
                    if not 'Enabled' in attributes:
                        attributes = ['Disabled']
                    else:

                        # Remove the present (we add this priv only if it present)
                        if 'Present' in attributes:
                            attributes.remove('Present')

                    process_security[int(pid)]['Privs'].append((int(value), str(name), ",".join(attributes), str(desc)))

            # Specific version checkes.

            # Check debug.
            if int(self.kaddr_space.profile.metadata.get('major')) > 5 and int(
                    self.kaddr_space.profile.metadata.get('minor')) > 1:
                isDebug = "Debuged" if e_proc.Flags & 0x2 else ""  # e_proc.Flags.NoDebugInherit

            # Version 6.3 -> 1703
            if int(self.kaddr_space.profile.metadata.get('major')) == 6 and (
                    int(self.kaddr_space.profile.metadata.get('minor')) == 3 or int(
                    self.kaddr_space.profile.metadata.get('minor')) == 3 and int(
                    self.kaddr_space.profile.metadata.get('build')) < 1709):
                cfg = "Enable" if e_proc.Flags & 0x00000010 else "Disable"  # ControlFlowGuardEnabled
            elif int(self.kaddr_space.profile.metadata.get('major')) == 6 and int(
                    self.kaddr_space.profile.metadata.get('minor')) == 4 and int(
                    self.kaddr_space.profile.metadata.get('build')) > 1709:
                cfg = "Enable" if e_proc.MitigationFlagsValues.ControlFlowGuardEnabled else "Disable"

            # Colored .Net processes. (os is vista or later)
            if int(self.kaddr_space.profile.metadata.get(
                    'major')) > 5 and e_proc.CrossSessionCreate == 1 and e_proc.WriteWatch == 1\
                    and not "(Colored in yellow because this is a .Net process)" in process_comments[int(pid)]: # OverrideAddressSpace ?
                process_comments[int(pid)] += "(Colored in yellow because this is a .Net process)"
                process_comments['pidColor'][int(pid)] = "yellow"

            # Colored Immersive process. (os is vista or later)
            TOKEN_LOWBOX = 0x4000  # this flag mean this is AppContainer!.
            if int(self.kaddr_space.profile.metadata.get('major')) > 5 and int(self.kaddr_space.profile.metadata.get(
                    'minor')) > 1 and e_proc.Job != 0 and proc_token.TokenFlags & TOKEN_LOWBOX or any(
                    "S-1-15-2-" in sid for sid in proc_token.get_sids())\
                    and not "(Colored in turquoise because this is a Immersive process)" in process_comments[int(pid)]: # find immersive process #
                process_comments[int(pid)] += "(Colored in turquoise because this is a Immersive process)"
                process_comments['pidColor'][int(pid)] = "turquoise1"
                integrity = 'AppContainer' if integrity not in integrity_levels else integrity

            protection = 'Disable'
            # Colored Protected process. (os is vista or later)
            if int(self.kaddr_space.profile.metadata.get('major')) > 5 and int(self.kaddr_space.profile.metadata.get(
                    'minor')) > 1 and e_proc.Protection.Type > 0\
                    and not "(Colored in purple because this is a Protected process)" in process_comments[int(pid)]:  # e_proc.Protection.Type==1: PsProtectionSingUntyMalwareLight, if 2 then is stronget and if 0 then no protection:###e_proc.Flag2&0x800 6.0-6.1#find protected process # _proc.Protection.Type==1: PsProtectionSingUntyMalwareLight, if 2 then is stronget and if 0 then no protection ###e_proc.Flag2&0x800 6.0-6.1and hasattr(e_proc, "Protection")
                process_comments[int(pid)] += "(Colored in purple because this is a Protected process)"
                process_comments['pidColor'][int(pid)] = "purple"
                protection = 'Protected ()'.format(e_proc.Protection.Level) if not protect_signer_by_level.has_key(
                    int(e_proc.Protection.Level)) else protect_signer_by_level[int(e_proc.Protection.Level)]
            elif int(self.kaddr_space.profile.metadata.get('major')) > 5:  # Check if win7
                protection = 'Protected' if int(
                    get_right_member(e_proc, ["ProtectedProcess"]) or -1) == 1 else 'Disable'

            # Create the process_performance
            process_performance[int(pid)] = (
                int(e_proc.Pcb.BasePriority), int(e_proc.Pcb.KernelTime), int(e_proc.Pcb.UserTime),
                int(e_proc.Pcb.KernelTime + e_proc.Pcb.UserTime), int(get_right_member(e_proc, ['Pcb.CycleTime']) or -1),
                # cpu
                int(e_proc.CommitCharge * 4), int(e_proc.CommitChargePeak * 4), int(e_proc.VirtualSize),
                int(get_right_member(e_proc, ['Vm.PageFaultCount', 'Vm.Instance.PageFaultCount']) or -1), 'not supported',
                # vm
                int(get_right_member(e_proc, ['Vm.Flags.MemoryPriority', 'Vm.Flags.MemoryPriority']) or -1),
                int((get_right_member(e_proc, ['Vm.WorkingSetSize', 'Vm.Instance.WorkingSetSize']) or -1) * 4), int((
                                                                                                                            get_right_member(
                                                                                                                                e_proc,
                                                                                                                                [
                                                                                                                                    'Vm.WorkingSetPrivateSize',
                                                                                                                                    'Vm.Instance.WorkingSetPrivateSize']) or -1) * 4),
            'not supported', 'not supported',
                int((get_right_member(e_proc, ['Vm.PeakWorkingSetSize', 'Vm.Instance.PeakWorkingSetSize']) or -1) * 4),
                # pm (fix on win10)
                int(get_right_member(e_proc, ['DefaultIoPriority']) or -1), int(e_proc.ReadTransferCount.LowPart), -1, -1,
                int(e_proc.WriteTransferCount.LowPart), -1, -1, int(e_proc.OtherTransferCount.LowPart), -1, -1,
                # i/o not sure if e_proc.WriteOperationCount | e_proc.WriteTransferCount (on them all).
                int(e_proc.ObjectTable.HandleCount or -1),
                int(get_right_member(e_proc, ['ObjectTable.HandleCountHighWatermark']) or -1), 'not supported',
            'not supported')  # e_proc.ObjectTable.HandleCountHighWatermark

            # Go all over the threads inside the process.
            total_cpu_time = float(sum([process_performance[c_pid][3] for c_pid in process_performance]))
            termi_threads = suspend_threads = 0
            cpu = "Terminate({})".format(
                        round((process_performance[int(pid)][3] / total_cpu_time) * 100, 3))
            for thread in e_proc.ThreadListHead.list_of_type("_ETHREAD", "ThreadListEntry"):
                thread_flag = str(thread_flags[int(thread.CrossThreadFlags)] if thread_flags.has_key(
                    thread.CrossThreadFlags) else thread.CrossThreadFlags)
                process_threads[int(e_proc.UniqueProcessId)][int(thread.Cid.UniqueThread)] = (
                    int(thread.Cid.UniqueThread),
                    hex(thread.StartAddress) if isinstance(thread.StartAddress, long) or isinstance(thread.StartAddress, int) else str(thread.StartAddress),
                    str(thread_flag),
                    hex(thread.Tcb.StackBase) if isinstance(thread.Tcb.StackBase, long) or isinstance(thread.Tcb.StackBase, int) else str(thread.Tcb.StackBase),
                    int(thread.Tcb.BasePriority),
                    int(thread.Tcb.Priority),
                    int(thread.Tcb.UserTime),
                    int(thread.Tcb.KernelTime),
                    str(thread.CreateTime),
                    str(thread.obj_offset))
                if 'PS_CROSS_THREAD_FLAGS_TERMINATED' in str(thread.CrossThreadFlags) or int(
                        thread.ExitTime) != 0:
                    termi_threads += 1

                # If thread state is wait(5)      and wait reason is suspend(5) the thread is susspend (so we wrap it with not state)
                elif int(thread.Tcb.State) == 5 and int(thread.Tcb.WaitReason) == 5:
                    suspend_threads += 1

            else:
                if termi_threads + suspend_threads != len(process_threads[int(pid)]):
                    cpu = "{}".format(round((process_performance[int(pid)][3] / total_cpu_time) * 100, 3))
                elif termi_threads == len(process_threads[int(pid)]):
                    cpu = "Terminating({})".format(
                        round((process_performance[int(pid)][3] / total_cpu_time) * 100, 3))
                elif termi_threads + suspend_threads == len(process_threads[int(pid)]):
                    cpu = "Suspended ({})".format(
                        round((process_performance[int(pid)][3] / total_cpu_time) * 100, 3))


            # Get all system drivers.
            if pid == 4:
                modlist = win32.modules.lsmod(self.kaddr_space)
                for mod in modlist:
                    if not process_bases[int(pid)]["dlls"].has_key(str(mod.BaseDllName)):
                        process_dlls[int(pid)].append(str(mod.FullDllName or 'Failed to get device name on address: {}'.format(mod.DllBase)))
                        process_bases[int(pid)]["dlls"][str(mod.BaseDllName)] = int(mod.DllBase)
                        process_bases[4]['ldr'][str(mod.BaseDllName)] = int(mod.obj_offset)
                        if not pe_comments['pid'][int(pid)].has_key(str(mod.FullDllName or 'Failed to get device name on address: {}'.format(mod.DllBase))):
                            pe_comments['pid'][int(pid)][str(mod.FullDllName or 'Failed to get device name on address: {}'.format(mod.DllBase))] = ['Write Your Comments Here.', 'white']

            # Get all process load dlls.
            else:
                for c_dll in e_proc.get_load_modules():
                    if not process_bases[int(pid)]["dlls"].has_key(str(c_dll.BaseDllName)):
                        process_dlls[int(pid)].append(str(c_dll.FullDllName or 'Failed to get dll name on address: {}'.format(c_dll.DllBase)))
                        process_bases[int(pid)]["dlls"][str(c_dll.BaseDllName)] = int(c_dll.DllBase)
                        process_bases[int(pid)]['ldr'][str(c_dll.BaseDllName)] = int(c_dll.obj_offset)
                        if not pe_comments['pid'][int(pid)].has_key(str(c_dll.FullDllName or 'Failed to get dll name on address: {}'.format(c_dll.DllBase))):
                            pe_comments['pid'][int(pid)][str(c_dll.FullDllName or 'Failed to get dll name on address: {}'.format(c_dll.DllBase))] = ['Write Your Comments Here.', 'white']

            process = "{} {}".format(find_number_of_parents(e_proc) * "?/?", e_proc.ImageFileName) #str(e_proc.ImageFileName)# "{} {}".format(find_number_of_parents(pid, e_proc.CreateTime) * "?\?", e_proc.ImageFileName) #find_number_of_parents #

            process_name = str(e_proc.ImageFileName)

            peb = e_proc.Peb
            # For Processes with no peb struct (like system, pico and minimal)
            if peb:
                session = peb.SessionId if peb.SessionId else -1
                cl = peb.ProcessParameters.CommandLine
                path = peb.ProcessParameters.ImagePathName
                wt = peb.ProcessParameters.WindowTitle
                cd = peb.ProcessParameters.CurrentDirectory.DosPath
                di = peb.ProcessParameters.DesktopInfo
                noh = peb.NumberOfHeaps if peb.NumberOfHeaps else -1

            createT = e_proc.CreateTime
            pfc = get_right_member(e_proc, ['Vm.PageFaultCount', 'Vm.Instance.PageFaultCount'])
            pwss = get_right_member(e_proc, ['Vm.PeakWorkingSetSize', 'Vm.Instance.PeakWorkingSetSize']) * 4
            ws = get_right_member(e_proc, ['Vm.WorkingSetSize', 'Vm.Instance.WorkingSetSize']) * 4

            # startregion from win7
            wsp = int((get_right_member(e_proc, ['Vm.WorkingSetPrivateSize',
                                                 'Vm.Instance.WorkingSetPrivateSize']) or -1) * 4)  # get_right_member(e_proc, ['Vm.WorkingSetPrivateSize']) or " "
            aslr = "Disable" if get_right_member(e_proc, ['StackRandomizationDisabled',
                                                          'MitigationFlagsValues.StackRandomizationDisabled']) == 1 else "Enable"
            sc = get_right_member(e_proc, ['Pcb.StackCount.StackCount', 'Pcb.StackCount'])
            cycles = get_right_member(e_proc, ['Pcb.CycleTime']) or ' '
            it = 32 if e_proc.IsWow64 else 64
            # end from win7

            # Check them (save the number of the pages, sp page *4096/k[represent in k])
            pb = e_proc.CommitCharge * 4

            priority = e_proc.Pcb.BasePriority
            ppd = e_proc.CommitChargePeak * 4
            vs = e_proc.VirtualSize * 4
            pvs = e_proc.PeakVirtualSize * 4
            Prefetch = e_proc.LaunchPrefetched
            dep = "DEP" if e_proc.Pcb.Flags.ExecuteDisable == 0 else "NOP"
            # integrity = integrity_levels[int(proc_token.IntegrityLevelIndex)] if proc_token.IntegrityLevelIndex < len(integrity_levels) else int(proc_token.IntegrityLevelIndex)
            ct = int(e_proc.Pcb.KernelTime) + int(e_proc.Pcb.UserTime)
            new_list_all.append([str(this_item) for this_item in (process, pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc)])

            # Go all over the old data and override the specific process in the old data, also update the table.
            count = 0
            for tup in self.list_all:

                # Check if this process exist (by process name, process id and parent process id).
                if (int(pid), int(ppid)) == (int(tup[1]), int(tup[2])):

                    # Check if nothing change in this process
                    if new_list_all[-1] == tup:
                        break

                    process_tree_data[count] = [str(item) for item in (process, pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc)]
                    self.list_all[count] = [str(this_item) for this_item in (process, pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc)]
                    # Update the table (and the visual table)
                    def update_table(data):
                        rows = main_table.get_all_children(main_table.tree, "", False)
                        for row, row_parent in rows:
                            process, pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc = main_table.tree.item(row)['values']
                            if (int(pid), int(ppid)) == (int(data[1]), int(data[2])) :
                                break
                        main_table.tree.item(row, values=data)
                        main_table.visual_drag.item(row, values=data)

                    # Replace " with ' because of some bug that we cant insert item like this - > ['" \ "  ']
                    # but item like this work: ["'\ ' "]
                    queue.put((update_table, ([str(this_item).replace('"', "'") for this_item in (' {}'.format(process_name), pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles,wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc)],)))

                    break

                count += 1
            # New Process Alert
            else:

                # Updates the data tables
                with lock:
                    c_index = find_index_of_proc_ppid_in_list(self.list_all, [str(this_item) for this_item in (process, pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc)])
                    self.list_all.insert(c_index, [str(this_item) for this_item in (process, pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc)])
                    process_tree_data.insert(c_index, [str(item) for item in (process, pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc)])

                queue.put((self.create_new_proc, (([' {}'.format(e_proc.ImageFileName),] + self.list_all[process_counter][1:]),)))

            process_counter += 1

        # To update again after it finished
        #self.list_all = new_list_all
        self.memtriage_update()

    def create_new_proc(self, process_data):
        global tree_view_data
        global process_tree_data
        global main_table

        print '[+] new process: {}'.format(process_data)

        new_proc_ppid = process_data[2]


        rows =  main_table.get_all_children(main_table.tree, "", False)
        for row, row_parent in rows:
            item = process, pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc = main_table.tree.item(row)['values']

            if pid == new_proc_ppid:
                item = [str(c_item).replace('{', r'\{').replace('}', r'\}').decode('utf-8',errors='ignore') for c_item in item]
                c_tag = re.sub('[^\S0-9a-zA-Z]', '_', str(item[self.text_by_item]))
                main_table.tree.insert(row, END, values=item, text=item[main_table.text_by_item], tags=c_tag)
                main_table.visual_drag.insert(row, END, values=item, text=item[main_table.text_by_item], tags=c_tag)
                break


        # Update the tree_view_data
        tree_view_data = [(main_table.tree.set(child[0], 'Process'), child)
                          for child in main_table.get_all_children(main_table.tree)]

    def calculate(self):
        """
        Return a list in the right order and update
        process_performance, process_dlls, process_bases, process_token
        """

        # From Saved File
        if hasattr(self, "calc_return"):
            for item in self.calc_return:
                yield item
            return # Make it done here so we dont have pslist twice

        global process_dlls
        global process_comments
        global process_bases
        global process_tree_data
        global process_performance
        global process_token
        global pe_comments
        global process_threads
        global process_security

        #https://docs.microsoft.com/en-us/previous-versions/dotnet/articles/bb625963(v=msdn.10)?redirectedfrom=MSDN
        #                  low            medium        high             system
        integrity_sids = ["S-1-16-4096", "S-1-16-8192", "S-1-16-12288", "S-1-16-16384"]
        integrity_levels = ["Untrusted", "Low", "Medium", "High", "System"]

        #default_user_integrity = {"LocalSystem": "System", "LocalService": "System", "NetworkService": "System", "Administrators": "High", "Backup Operators": "High", "Network Configuration Operators": "High", "Cryptographic Operators": "High", "Authenticated Users": "Medium", "Everyone": "Low", "Anonymous": "Untrusted"}
        """
        00 S-1-5-21-1712426984-1618080182-1209977580-513 Attributes - Mandatory Default Enabled
        01 S-1-1-0 Attributes - Mandatory Default Enabled
        02 S-1-5-32-544 Attributes - Mandatory Default Enabled Owner
        03 S-1-5-32-545 Attributes - Mandatory Default Enabled
        04 S-1-5-2 Attributes - Mandatory Default Enabled
        05 S-1-5-11 Attributes - Mandatory Default Enabled
        06 S-1-5-21-1712426984-1618080182-1209977580-1110 Attributes - Mandatory Default Enabled
        """

        # process protection:
        """ Process protection siner levels (the dozen from the hexa value in the dict)
        Signer      level         description
        WinSystem     7           System and minimal process
        WinTcp        6           Critical Windows components PROCESS_TERMINATE is unavailable.
        Windows       5           Important Windows Components handling sensitive data
        LSA           4           Lsass.exe (if configured to run protected).
        Antimalware   3           Antimalware service processes, including 3rd party, PROCESS_TERMINATE is unavailable.
        CodeGen       2           .NET native code generation.
        Authenticode  1           Hosting DRM content.
        None          0           Process is not protected.
        """
        protect_signer_by_level = {0x72: 'System Level Protection', 0x62: 'PsProtectedSignerWinTcb', 0x61: 'PsProtectedSignerWinTcb-Light', 0x52: 'PsProtectedSignerWindows', 0x51: 'PsProtectedSignerWindows-Light', 0x41: 'PsProtectedSignerLsa-Light', 0x31: 'PsProtectedSignerAntimalware-Light', 0x21: 'PsProtectedSignerAuthenCode', 0x11: 'PsProtectedSignerAuthenCode-Light'}

        # Token security attributes:
        """
        #define SE_GROUP_MANDATORY                 (0x00000001L)
        #define SE_GROUP_ENABLED_BY_DEFAULT        (0x00000002L)
        #define SE_GROUP_ENABLED                   (0x00000004L)
        #define SE_GROUP_OWNER                     (0x00000008L)
        #define SE_GROUP_USE_FOR_DENY_ONLY         (0x00000010L)
        #define SE_GROUP_INTEGRITY                 (0x00000020L)
        #define SE_GROUP_INTEGRITY_ENABLED         (0x00000040L)
        #define SE_GROUP_LOGON_ID                  (0xC0000000L)
        #define SE_GROUP_RESOURCE                  (0x20000000L)
        """
        token_security_attributes = {0: 'Attached (process user name)', 7: 'Mandatory', 10:'Owner', 14:'Owner', 16: 'Deny', 96: 'Integrity'}

        # Add new privilege to the privilege dictionary (for windows 10).
        privileges.PRIVILEGE_INFO[36] = ("SeDelegateSessionUserImpersonatePrivilege", "Obtain an impersonation token for another user in the same session.")

        # Thread flags mask
        thread_flags = {0: "Terminate", 1: "Dead", 2: "Hide from debug", 3: "Impersonating", 4: "System", 5: "Hard Error Disable", 6: "Break On Termination", 7: "Skip Creation Message", 8: "Skip Terminate Message"}

        # Image Type, Context Switch, Windows Status,
        for proc_T in self.return_pstree():
            process, pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc = [str(i-i-1) for i in range(43)]
            e_proc = proc_T[0]
            pid = e_proc.UniqueProcessId
            ppid = e_proc.InheritedFromUniqueProcessId
            proc_token = e_proc.get_token()

            # Create the process_dlls and proc_bases
            process_comments[int(pid)] = "Write Your Comments Here."
            process_bases[int(pid)] = {"proc": e_proc, "dlls": {}}
            process_bases[int(pid)]["dlls"] = {}
            process_bases[int(pid)]["ldr"] = {}
            process_dlls[int(pid)] = []
            pe_comments['pid'][int(pid)] = {}

            # Create dict inside the process_threads[pid]
            process_threads[int(e_proc.UniqueProcessId)] = {}

            # Create a dictionary inside the process_security[pid] if not exists.
            if not process_security.has_key(int(e_proc.UniqueProcessId)):
                process_security[int(e_proc.UniqueProcessId)] = {}

            # Create a list inside the process_security[pid]['Privs']
            if not process_security[int(e_proc.UniqueProcessId)].has_key('Privs'):
                process_security[int(e_proc.UniqueProcessId)]['Privs'] = []

            # Add the session to the process_security[pid]['session']
            process_security[int(e_proc.UniqueProcessId)]['session'] = int(e_proc.ProcessInSession)

            # Go all over the threads inside the process.
            for thread in e_proc.ThreadListHead.list_of_type("_ETHREAD", "ThreadListEntry"):
                thread_flag = str(thread_flags[int(thread.CrossThreadFlags)] if thread_flags.has_key(
                    thread.CrossThreadFlags) else thread.CrossThreadFlags)
                process_threads[int(e_proc.UniqueProcessId)][int(thread.Cid.UniqueThread)] = (int(thread.Cid.UniqueThread),
                                                                                            hex(thread.StartAddress) if isinstance(thread.StartAddress, long) or isinstance(thread.StartAddress, int) else str(thread.StartAddress),
                                                                                            str(thread_flag),
                                                                                            hex(thread.Tcb.StackBase) if isinstance(thread.Tcb.StackBase, long) or isinstance(thread.Tcb.StackBase, int) else str(thread.Tcb.StackBase),
                                                                                            int(thread.Tcb.BasePriority),
                                                                                            int(thread.Tcb.Priority),
                                                                                            int(thread.Tcb.UserTime),
                                                                                            int(thread.Tcb.KernelTime),
                                                                                            str(thread.CreateTime),
                                                                                            str(thread.obj_offset))

            # This item update lated (on update_table_all)
            un, cn, Description, version, intName, ofn = " ", " ", " ", " ", " ", " "

            threads = e_proc.ActiveThreads
            handles = e_proc.ObjectTable.HandleCount if e_proc.ObjectTable.HandleCount else -1 if not process_handles.has_key(int(pid)) else len(process_handles[int(pid)])

            # add token info
            token_user = "{}\{}".format(str(get_right_member(proc_token, ['LogonSession.AuthorityName'])), str(get_right_member(proc_token, ['LogonSession.AccountName'])))
            token_session = str(get_right_member(proc_token, ['LogonSession.LogonId.LowPart']))#int()
            token_session_id = str(get_right_member(proc_token, ['SessionId']))
            token_elevated = ""
            token_virtualized = ""
            token_protected = ""
            process_token[int(pid)] = (str(proc_token.v()), token_user, token_session, token_session_id, token_elevated, token_virtualized, token_protected)
            #

            integrity = int(get_right_member(proc_token, ["IntegrityLevelIndex"]) or -1)
            integrity = "{} (Token)".format(integrity_levels[int(proc_token.IntegrityLevelIndex)] if int(get_right_member(proc_token, ["IntegrityLevelIndex"]) or 99) < len(integrity_levels) else integrity)
            if not process_security.has_key(int(pid)):
                process_security[int(pid)] = {}
            if not process_security[int(pid)].has_key('Groups'):
                process_security[int(pid)]['Groups'] = []
            un = "Searching..."
            first_sid_name = True
            proc_token_sid_array = proc_token.UserAndGroups.dereference()
            sid_count = 0
            for sid_string in proc_token.get_sids():

                # Getting the attribute flag
                attr = proc_token_sid_array[sid_count].Attributes
                sid_count += 1

                sid_flag = attr

                if attr > 9999:
                    sid_flag = 'Logon ID'
                else:
                    for sid_secure in token_security_attributes:
                        if int(attr) == sid_secure:
                            sid_flag = token_security_attributes[sid_secure] if sid_secure in token_security_attributes else str(sid_secure)
                            break
                    else:
                        sid_flag = 'Unsupported ({})'.format(attr)

                # Getting the sid string
                sid_name = "Searching..."

                if has_crypto and sid_string in getsids.well_known_sids:
                    sid_name = str(getsids.well_known_sids[sid_string])
                    #if sid_name in default_user_integrity:
                    #	integrity = default_user_integrity[sid_name]

                if sid_string in integrity_sids:
                    integrity = "{} (SID)".format(integrity_levels[1:][integrity_sids.index(sid_string)])

                # The first sid display is the username
                if first_sid_name:
                    first_sid_name = False
                    un = sid_name

                process_security[int(pid)]['Groups'].append((sid_name, sid_string, sid_flag))

            # Go all over the privileges inside the process token.
            for value, present, enabled, default in proc_token.privileges():
                # Skip privileges whose bit positions cannot be
                # translated to a privilege name
                try:
                    name, desc = privileges.PRIVILEGE_INFO[int(value)]
                except KeyError:
                    continue

                # Set the attributes
                attributes = []
                if present:
                    attributes.append("Present")
                if default:
                    attributes.append("Default")
                if enabled:
                    attributes.append("Enabled")

                if attributes != []:

                    # By default privs are disable (we need to enable them to use them).
                    if not 'Enabled' in attributes:
                        attributes = ['Disabled']
                    else:

                        # Remove the present (we add this priv only if it present)
                        if 'Present' in attributes:
                            attributes.remove('Present')

                    process_security[int(e_proc.UniqueProcessId)]['Privs'].append((int(value), str(name), ",".join(attributes), str(desc)))


            # Specific version checkes.

            # Check debug.
            if int(self.kaddr_space.profile.metadata.get('major')) > 5 and int(self.kaddr_space.profile.metadata.get('minor')) > 1:
                isDebug = "Debuged" if e_proc.Flags & 0x2 else ""#e_proc.Flags.NoDebugInherit

            # Version 6.3 -> 1703
            if int(self.kaddr_space.profile.metadata.get('major')) == 6 and (int(self.kaddr_space.profile.metadata.get('minor')) == 3 or int(self.kaddr_space.profile.metadata.get('minor')) == 3 and int(self.kaddr_space.profile.metadata.get('build')) < 1709):
                cfg = "Enable" if e_proc.Flags & 0x00000010 else "Disable"# ControlFlowGuardEnabled
            elif int(self.kaddr_space.profile.metadata.get('major')) == 6 and int(self.kaddr_space.profile.metadata.get('minor')) == 4 and int(self.kaddr_space.profile.metadata.get('build')) > 1709:
                cfg = "Enable" if e_proc.MitigationFlagsValues.ControlFlowGuardEnabled else "Disable"

            # Colored .Net processes. (os is vista or later)
            if int(self.kaddr_space.profile.metadata.get('major')) > 5 and e_proc.CrossSessionCreate == 1 and e_proc.WriteWatch == 1: # OverrideAddressSpace ?
                process_comments[int(pid)] += "(Colored in yellow because this is a .Net process)"
                process_comments['pidColor'][int(pid)] = "yellow"

            # Colored Immersive process. (os is vista or later)
            TOKEN_LOWBOX = 0x4000 # this flag mean this is AppContainer!.
            if int(self.kaddr_space.profile.metadata.get('major')) > 5 and int(self.kaddr_space.profile.metadata.get('minor')) > 1 and e_proc.Job !=0 and proc_token.TokenFlags & TOKEN_LOWBOX or any("S-1-15-2-" in sid for sid in proc_token.get_sids()):#find immersive process #
                process_comments[int(pid)] += "(Colored in turquoise because this is a Immersive process)"
                process_comments['pidColor'][int(pid)] = "turquoise1"
                integrity = 'AppContainer' if integrity not in integrity_levels else integrity

            protection = 'Disable'
            # Colored Protected process. (os is vista or later)
            if int(self.kaddr_space.profile.metadata.get('major')) > 5 and int(self.kaddr_space.profile.metadata.get('minor')) > 1 and e_proc.Protection.Type > 0: #e_proc.Protection.Type==1: PsProtectionSingUntyMalwareLight, if 2 then is stronget and if 0 then no protection:###e_proc.Flag2&0x800 6.0-6.1#find protected process # _proc.Protection.Type==1: PsProtectionSingUntyMalwareLight, if 2 then is stronget and if 0 then no protection ###e_proc.Flag2&0x800 6.0-6.1and hasattr(e_proc, "Protection")
                process_comments[int(pid)] += "(Colored in purple because this is a Protected process)"
                process_comments['pidColor'][int(pid)] = "purple"
                protection = 'Protected ()'.format(e_proc.Protection.Level) if not protect_signer_by_level.has_key(int(e_proc.Protection.Level)) else protect_signer_by_level[int(e_proc.Protection.Level)]
            elif int(self.kaddr_space.profile.metadata.get('major')) > 5: # Check if win7
                protection = 'Protected' if int(get_right_member(e_proc, ["ProtectedProcess"]) or -1) == 1 else 'Disable'


            # Create the process_performance
            process_performance[int(pid)] =(int(e_proc.Pcb.BasePriority), int(e_proc.Pcb.KernelTime), int(e_proc.Pcb.UserTime), int(e_proc.Pcb.KernelTime + e_proc.Pcb.UserTime), int(get_right_member(e_proc, ['Pcb.CycleTime']) or -1),#cpu
                                int(e_proc.CommitCharge*4),int(e_proc.CommitChargePeak*4), int(e_proc.VirtualSize), int(get_right_member(e_proc, ['Vm.PageFaultCount', 'Vm.Instance.PageFaultCount']) or -1), 'not supported',#vm
                                int(get_right_member(e_proc, ['Vm.Flags.MemoryPriority', 'Vm.Flags.MemoryPriority']) or -1), int((get_right_member(e_proc, ['Vm.WorkingSetSize', 'Vm.Instance.WorkingSetSize']) or -1)*4 ), int((get_right_member(e_proc, ['Vm.WorkingSetPrivateSize','Vm.Instance.WorkingSetPrivateSize'])or -1)*4), 'not supported', 'not supported', int((get_right_member(e_proc, ['Vm.PeakWorkingSetSize', 'Vm.Instance.PeakWorkingSetSize'])or -1 )*4),#pm (fix on win10)
                                int(get_right_member(e_proc, ['DefaultIoPriority']) or -1), int(e_proc.ReadTransferCount.LowPart), -1, -1, int(e_proc.WriteTransferCount.LowPart), -1, -1, int(e_proc.OtherTransferCount.LowPart), -1, -1,#i/o not sure if e_proc.WriteOperationCount | e_proc.WriteTransferCount (on them all).
                                int(e_proc.ObjectTable.HandleCount or -1), int(get_right_member(e_proc, ['ObjectTable.HandleCountHighWatermark']) or -1), 'not supported', 'not supported')#e_proc.ObjectTable.HandleCountHighWatermark

            # Get all system drivers.
            if pid == 4:
                modlist = win32.modules.lsmod(self.kaddr_space)
                for mod in modlist:
                    process_dlls[4].append(str(mod.FullDllName or 'Failed to get device name on address: {}'.format(mod.DllBase)))
                    process_bases[4]["dlls"][str(mod.BaseDllName)] = int(mod.DllBase)
                    process_bases[4]['ldr'][str(mod.BaseDllName)] = int(mod.obj_offset)
                    pe_comments['pid'][4][str(mod.FullDllName or 'Failed to get device name on address: {}'.format(mod.DllBase))] = ['Write Your Comments Here.', 'white']
            # Get all process load dlls.
            else:
                for c_dll in e_proc.get_load_modules():
                    process_dlls[int(pid)].append(str(c_dll.FullDllName or 'Failed to get dll name on address: {}'.format(c_dll.DllBase)))
                    process_bases[int(pid)]["dlls"][str(c_dll.BaseDllName)] = int(c_dll.DllBase)
                    process_bases[int(pid)]['ldr'][str(c_dll.BaseDllName)] = int(c_dll.obj_offset)
                    pe_comments['pid'][int(pid)][str(c_dll.FullDllName or 'Failed to get dll name on address: {}'.format(c_dll.DllBase))] = ['Write Your Comments Here.', 'white']

            process = "{} {}".format(proc_T[1] * "?\?", e_proc.ImageFileName)

            peb = e_proc.Peb
            # For Processes with no peb struct (like pico and minimal)
            if peb:
                session = peb.SessionId if peb.SessionId else -1
                cl = peb.ProcessParameters.CommandLine
                path = peb.ProcessParameters.ImagePathName
                wt = peb.ProcessParameters.WindowTitle
                cd = peb.ProcessParameters.CurrentDirectory.DosPath
                di = peb.ProcessParameters.DesktopInfo
                noh = peb.NumberOfHeaps if peb.NumberOfHeaps else -1

            createT = e_proc.CreateTime
            pfc = get_right_member(e_proc, ['Vm.PageFaultCount', 'Vm.Instance.PageFaultCount'])
            pwss = get_right_member(e_proc, ['Vm.PeakWorkingSetSize', 'Vm.Instance.PeakWorkingSetSize'])*4
            ws = get_right_member(e_proc, ['Vm.WorkingSetSize', 'Vm.Instance.WorkingSetSize'])*4

            #startregion from win7
            wsp = int((get_right_member(e_proc, ['Vm.WorkingSetPrivateSize','Vm.Instance.WorkingSetPrivateSize'])or -1)*4)#get_right_member(e_proc, ['Vm.WorkingSetPrivateSize']) or " "
            aslr = "Disable" if get_right_member(e_proc, ['StackRandomizationDisabled', 'MitigationFlagsValues.StackRandomizationDisabled']) == 1 else "Enable"
            sc = get_right_member(e_proc, ['Pcb.StackCount.StackCount', 'Pcb.StackCount'])
            cycles = get_right_member(e_proc,['Pcb.CycleTime']) or ' '
            it = 32 if e_proc.IsWow64 else 64
            #end from win7

            # Check them (save the number of the pages, sp page *4096/k[represent in k])
            pb = e_proc.CommitCharge*4

            priority = e_proc.Pcb.BasePriority
            ppd = e_proc.CommitChargePeak*4
            vs = e_proc.VirtualSize*4
            pvs = e_proc.PeakVirtualSize*4
            Prefetch = e_proc.LaunchPrefetched
            dep = "DEP" if e_proc.Pcb.Flags.ExecuteDisable == 0 else "NOP"
            #integrity = integrity_levels[int(proc_token.IntegrityLevelIndex)] if proc_token.IntegrityLevelIndex < len(integrity_levels) else int(proc_token.IntegrityLevelIndex)
            ct = int(e_proc.Pcb.KernelTime) + int(e_proc.Pcb.UserTime)
            process_tree_data.append([str(item) for item in (process, pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc)])
            yield process, pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc

    def render_text(self, outfd, data, root_tk=None):
        """
        Init all the gui
        :param outfd: the writer (not in use)
        :param data: the calculate data
        :param root_tk: gui Tk() if any
        :return: mainloop never return
        """
        global files_info, process_dlls, process_handles, process_bases, process_threads, process_connections, process_imports, process_env_var, process_security, process_performance, process_comments, tree_view_data, pfn_stuff, mft_explorer, files_scan, winobj_dict, reg_dict, service_dict, all_plugins
        global root
        global lock
        global queue
        global main_table

        # Wish you lock <3
        print "GL & HF <3 ATZ\n"

        # Get the main processes table items
        headers = ('Process', 'PID', 'PPID', 'CPU (%)', 'Private Bytes (KB)', 'Working Set (KB)', 'Description', 'Company Name', 'DEP', 'ASLR', 'CFG', 'Protected', 'Debugger Present', 'Prefetch', 'Threads', 'Handles', 'User Name', 'Session', 'Heap Count', 'Stack Count', 'PageFault Count', 'Desktop', 'Image Type', 'Context Switch', 'Windows Status', 'integrity', 'Priority', 'CPU Time', 'Cycles', 'Private Working Set (KB)', 'Peak Private Byte (KB)', 'Peak Working Set (KB)', 'Virtual Size (KB)', 'Peak Virtual Size (KB)', 'Created Time', 'Internal Name', 'Original File Name', 'Windows Title', 'Command Line', 'Path', 'Current Directory', 'Version', 'Address')
        list_all = []
        for process, pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc in data:

            good_list_table = []
            for item in [process, pid, ppid, cpu, pb, ws, Description, cn, dep, aslr, cfg, protection, isDebug, Prefetch, threads, handles, un, session, noh, sc, pfc, di, it, cs, winStatus, integrity, priority, ct, cycles, wsp, ppd, pwss, vs, pvs, createT, intName, ofn, wt, cl, path, cd, version, e_proc]:
                text = str(item)
                good_list_table.append(text.replace("\\", "/") if not str(text).isdigit() else text)

            list_all.append(list(good_list_table))


        # Get cpu time and process status[Running|Suspend|Terminate] by checking some flags.
        total_cpu_time = float(sum([process_performance[c_pid][3] for c_pid in process_performance]))
        for item in xrange(len(list_all)):

            # if process_threads.has_key(pid): (support for memtriage if some new processes created).
            if not process_threads.has_key(int(list_all[item][1])):#memtri
                continue

            # If the process has no threads mark as Terminate
            if len(process_threads[int(list_all[item][1])]) == 0:
                list_all[item][3] = "Terminate({})".format(round((process_performance[int(list_all[item][1])][3] / total_cpu_time) * 100, 3))
                continue

            list_all[item][3] = round((process_performance[int(list_all[item][1])][3] / total_cpu_time) * 100, 3)
            termi_threads = 0
            suspend_threads = 0
            for c_thread in process_threads[int(list_all[item][1])].values():

                thread_obj = obj.Object("_ETHREAD", c_thread[-1], self.kaddr_space)

                # Check if the flags is dead thread flag.
                if 'PS_CROSS_THREAD_FLAGS_TERMINATED' in  str(thread_obj.CrossThreadFlags) or int(thread_obj.ExitTime) != 0:
                    termi_threads += 1

                # If thread state is wait(5)      and wait reason is suspend(5) the thread is susspend (so we wrap it with not state)
                elif int(thread_obj.Tcb.State) == 5 and int(thread_obj.Tcb.WaitReason) == 5:
                    suspend_threads += 1

                # Check if there is a running thread that is not susspend and not terminated
                # And if so exit (because this proces is not terminated and not susspend).
                elif int(thread_obj.ExitTime) == 0:
                    break

            else:
                if termi_threads == len(process_threads[int(list_all[item][1])]):
                    list_all[item][3] = "Terminating({})".format(round((process_performance[int(list_all[item][1])][3] / total_cpu_time) * 100, 3))
                elif termi_threads + suspend_threads == len(process_threads[int(list_all[item][1])]):
                    list_all[item][3] = "Suspended ({})".format(round((process_performance[int(list_all[item][1])][3] / total_cpu_time) * 100, 3))


        # Creating the GUI
        root = root_tk or root or Tk()

        # If the user exit the load screen
        if not hasattr(root, "subprocess"):
            root = Tk()

        # Config default style.
        root.geometry('800x450')
        root.tk.call('tk', 'scaling', 1.4)
        self.style = s = ThemedStyle(root) if has_themes else ttk.Style()
        s.layout("Tab",[('Notebook.tab', {'sticky': 'nswe', 'children':
                         [('Notebook.padding', {'side': 'top', 'sticky': 'nswe', 'children':
                             [('Notebook.label', {'side': 'top', 'sticky': ''})],
                                                })],
                                        })])
        s.configure('Treeview', rowheight=21)
        s.configure("Tab", focuscolor=s.configure("white"))#["background"])
        s.configure('TFrame', background='white')
        s.configure("TButton", background="white", foreground="blue")
        s.configure("TLabel", background="white")
        s.configure("TLabelFrame", background="white", foreground="white")
        s.configure('IndicatorOff.TRadiobutton',
                   indicatorrelief=tk.FLAT,
                   indicatormargin=10,
                   indicatordiameter=-1,
                   relief=tk.RAISED,
                   focusthickness=5, highlightthickness=5, padding=5)

        # For creating disable like treeview.
        disabled_bg = s.lookup("TEntry", "fieldbackground", ("disabled",))
        disabled_fg = s.lookup("TEntry", "foreground", ("disabled",))
        s.map("Treeview", fieldbackground=[("disabled", disabled_bg)], foreground=[("disabled", disabled_fg)])

        root.title("Volatility Explorer")

        # Exit Popup
        def on_exit(none=None):
            '''
            Exit popup
            :param none: None (support event)
            :return: None
            '''
            if messagebox.askokcancel("Quit",
                                      "Do you really wish to quit?\n\nRECOMMENDED: saving your data onto a file before exiting allows you to later run it (using the -s option) without having to load"):
                self._run_main_loop = False
        root.protocol("WM_DELETE_WINDOW", on_exit)

        # Config some widget for the main tab.
        self.frames = {}
        root.NoteBook = self.NoteBook = NoteBook(root)
        self.pw = PanedWindow(self.NoteBook, orient='vertical')
        self.list_all = list_all
        main_table = treetable = ProcessesTable(self.pw, headers=headers, data=list_all, text_by_item=1, resize=True, display=headers[1:6])
        self.frames["Processes"] = treetable
        self.treetable = treetable
        treetable.tree['height'] = 12 if 12 < len(list_all) else len(list_all)

        # Create Menu bar.
        menubar = Menu(root)
        process_menu_bar = Menu(menubar, tearoff=0)
        self.view_menu_bar = view_menu_bar = Menu(menubar, tearoff=0)
        self.subview_menu_bar = subview_menu_bar = Menu(view_menu_bar, tearoff=0)
        find_menu_bar = Menu(menubar, tearoff=0)
        dump_menu = Menu(menubar, tearoff=0)
        options_menu = Menu(menubar, tearoff=0)
        self.style_menu = style_menu = Menu(options_menu, tearoff=0)
        file_menu_bar = Menu(menubar, tearoff=0)
        help = Menu(menubar, tearoff=0)
        process_menu_bar.add_command(label="Dlls (Ctrl+d)", command=lambda: treetable.control_d(0))
        process_menu_bar.add_command(label="Handles (Ctrl+h)", command=lambda: treetable.control_h(0))
        process_menu_bar.add_command(label="Network (Ctrl+n)", command=lambda: treetable.control_n(0))
        process_menu_bar.add_command(label="Properties in new tab", command=lambda: self.properties(0))
        process_menu_bar.add_command(label="Properties in main tab", command=lambda: self.s_properties(0))
        subview_menu_bar.add_command(label="Registry Explorer", command=lambda: self.s_control_r(0))
        subview_menu_bar.add_command(label="MFT Explorer", command=lambda: self.s_control_m(0))
        subview_menu_bar.add_command(label="File Explorer", command=lambda: self.s_control_e(0))
        subview_menu_bar.add_command(label="WinObj Explorer", command=lambda: self.s_control_w(0))
        subview_menu_bar.add_separator()
        subview_menu_bar.add_command(label="Process", command=lambda: self.s_control_t(0))
        subview_menu_bar.add_command(label="Modules", command=lambda: self.s_control_d(0))
        subview_menu_bar.add_command(label="Network", command=lambda: self.s_control_n(0))
        subview_menu_bar.add_command(label="Services", command=lambda: self.s_control_s(0))

        subview_menu_bar.add_separator()
        # subview_menu_bar.add_command(label="System Information", command=lambda: self.s_control_i(0)) # To Add
        # subview_menu_bar.entryconfig(9, background='red')
        subview_menu_bar.add_command(label="Help", command=lambda: self.s_control_h(0))
        subview_menu_bar.add_command(label="Properties in main tab", command=lambda: self.s_properties(0))
        view_menu_bar.add_cascade(label="Open Sub View", menu=subview_menu_bar)
        view_menu_bar.add_separator()
        view_menu_bar.add_command(label="Registry Explorer (Ctrl+r)", command=lambda: self.control_r(0))
        view_menu_bar.add_command(label="MFT Explorer (Ctrl+m)", command=lambda: self.control_m(0))
        view_menu_bar.add_command(label="File Explorer (Ctrl+e)", command=lambda: self.control_e(0))
        view_menu_bar.add_command(label="WinObj Explorer (Ctrl+w)", command=lambda: self.control_w(0))
        view_menu_bar.add_command(label="Process Tree (Ctrl+t)", command=lambda: self.control_t(0))
        view_menu_bar.add_command(label="Services (Ctrl+s)", command=lambda: self.control_s(0))
        # view_menu_bar.add_command(label="System Information (Ctrl+i)", command=lambda: self.control_i(0)) # To Add
        # view_menu_bar.entryconfig(8, background='red')
        view_menu_bar.add_separator()
        view_menu_bar.add_command(label="Select Columns... (Ctrl+c)", command=self.treetable.header_selected)
        view_menu_bar.add_command(label="Unalert all processes... (Ctrl+u)", command=self.treetable.unalert_all)
        view_menu_bar.add_separator()
        view_menu_bar.add_command(label="All your comments (Ctrl+a)", command=self.view_comments)
        find_menu_bar.add_command(label="Find Handles and Dlls (Ctrl+f)", command=lambda: self.treetable.control_f(0))
        dump_menu.add_command(label="Dump Registry Hives", command=self.dump_reg)
        dump_menu.add_command(label="Dump Event Log", command=self.dump_event_log)
        dump_menu.add_command(label="Dump Certs", command=self.dump_certs)
        options_menu.add_command(label="Options (Ctrl+o)", command=lambda: self.popup_options(0))
        self.all_themes = list(s.theme_names())

        for c_style in range(len(self.all_themes)):
            style_menu.add_command(label="{} style".format(self.all_themes[c_style]),  command=functools.partial(self.change_style, c_style))

        options_menu.add_cascade(label="Change Theme", menu=style_menu)
        self.menu_bg = s.lookup("TMenu", "background")

        #if 'smog' in self.all_themes:
        #	self.all_themes.remove("smog")# may crush the program.

        # Display a working theme (that the treeview colors work).
        if sys.platform != 'win32':
            if 'clearlooks' in self.all_themes:
                self.style.theme_use('clearlooks')
                self.style_menu.entryconfig(self.all_themes.index('clearlooks'), background='LightBlue3')
            elif 'clam' in self.all_themes:
                self.style.theme_use('clam')
                self.style_menu.entryconfig(self.all_themes.index('clam'), background='LightBlue3')

        # Run on win32 (windows)
        else:
            if 'vista' in self.all_themes:
                self.style.theme_use('vista')
                self.style_menu.entryconfig(self.all_themes.index('vista'), background='LightBlue3')
            try:
                # Ask the user if he want to align the submenues from left to right
                from_left_to_right = "MenuDropAlignment    REG_SZ    1"
                align_data = subprocess.check_output(r'REG QUERY "HKCU\SOFTWARE\microsoft\windows nt\currentversion\windows"')
                if not from_left_to_right in align_data:
                    ans = messagebox.askquestion("Align Menu",
                                                 "On windows the default alingment is from right to left\nDo you want to change it to display from left from right (RECOMMENDED)")
                    if ans == 'yes':
                        print subprocess.check_output(r'REG ADD "HKCU\SOFTWARE\microsoft\windows nt\currentversion\windows" /v MenuDropAlignment /t REG_SZ /d 1 /f'), 'please logoff and on to make this work.'
            except Exception:
                print '[-] sorry unable to change the alingment'

        self.style.configure('blue.Horizontal.TProgressbar', background='blue')

        file_menu_bar.add_command(label="Save (cache file for this specific run)", command=self.save)
        file_menu_bar.add_command(label="Save As (cache file for this specific run)", command=lambda: self.save(tkFileDialog.askdirectory()))
        file_menu_bar.add_separator()
        file_menu_bar.add_command(label="Exit", command=on_exit)
        plugins_menu = Menu(menubar, tearoff=0)
        well_known_plugins_menu = Menu(plugins_menu, tearoff=0)
        all_plugins_menu = Menu(plugins_menu, tearoff=0)
        plugins_menu.add_cascade(label="Well Known", menu=well_known_plugins_menu)
        plugins_menu.add_cascade(label="All", menu=all_plugins_menu)

        # Insert all the well known plugins to the plugin menu item.
        well_known_plugins = ["apihooks", "malfind", "threadmap", "tokenimp", "screenshot", "consoles", "psxview", "shimcache", "shellbags", "userassist", "userhandles", "unloadedmodules", "wintree", "gahti", "gdt"]
        for plugin in range(len(well_known_plugins)):
            well_known_plugins_menu.add_command(label='{}'.format(well_known_plugins[plugin]),
                                         command=functools.partial(self.run_plugin, well_known_plugins[plugin]))

        # Insert all the plugin to the plugin menu item.
        for plugin in range(len(all_plugins[1])):
            all_plugins_menu.add_command(label='{}'.format(all_plugins[1][plugin]),
                                          command=functools.partial(self.run_plugin, all_plugins[1][plugin]))

        help.add_command(label="Display Help (F11)", command=lambda: self.control_h(0))
        help.add_command(label="About", command=self.about)

        # Add all the submenus to the main menu as cascade.
        menubar.add_cascade(label="File", menu=file_menu_bar)
        menubar.add_cascade(label="View", menu=view_menu_bar)
        menubar.add_cascade(label="Process", menu=process_menu_bar)
        menubar.add_cascade(label="Find", menu=find_menu_bar)
        menubar.add_cascade(label='Plugins', menu=plugins_menu)
        menubar.add_cascade(label='Dump', menu=dump_menu)
        menubar.add_cascade(label='Options', menu=options_menu)
        menubar.add_cascade(label='Help', menu=help)
        root.config(menu=menubar)


        # Create the menu buttons
        menuFrame = ttk.Frame(root)

        img = tk.PhotoImage(data=ICON)
        smaller_image = img.subsample(15, 15)

        main_properties_image = tk.PhotoImage(data=MAIN_PROPERTIES_ICON)
        main_properties_image_icon = main_properties_image.subsample(13, 13)

        lower_pane_image = tk.PhotoImage(data=LOWER_PANE_ICON)
        lower_pane_image_icon = lower_pane_image.subsample(11, 11)

        search_image = tk.PhotoImage(data=SEARCH_ICON)
        search_image_icon = search_image.subsample(12, 12)

        properties_image = tk.PhotoImage(data=PROPERTIES_ICON)
        properties_image_icon = properties_image.subsample(12, 12)

        save_image = tk.PhotoImage(data=SAVE_ICON)
        save_image_icon = save_image.subsample(12, 12)

        save_button = tk.Button(menuFrame, image=save_image_icon, command=lambda: self.save(tkFileDialog.askdirectory()), height=15, width=15)
        save_button.pack(side=tk.LEFT)
        ttk.Label(menuFrame, text='  |  ').pack(side=tk.LEFT)
        ToolTip(save_button, 'Save As(cache file for this specific run)')

        properties_button = tk.Button(menuFrame, image=properties_image_icon, command=self.properties, height=15, width=15)
        properties_button.pack(side=tk.LEFT)
        ttk.Label(menuFrame, text='  |  ').pack(side=tk.LEFT)
        ToolTip(properties_button, 'Process Properties')

        search_button = tk.Button(menuFrame, image=search_image_icon, command=self.treetable.control_f, height=15, width=15)
        search_button.pack(side=tk.LEFT)
        ttk.Label(menuFrame, text='  |  ').pack(side=tk.LEFT)
        ToolTip(search_button, 'Find Handle or Dll [Ctrl+F]')

        lower_pane_button = tk.Button(menuFrame, image=lower_pane_image_icon, command=self.treetable.control_d, height=15, width=15)
        lower_pane_button.pack(side=tk.LEFT)
        ttk.Label(menuFrame, text='  |  ').pack(side=tk.LEFT)
        ToolTip(lower_pane_button, 'Display/Hide Lower Pane\n[Ctrl+D] -> Display Dlls\n[Ctrl+H] -> Display Handles\n[Ctrl+N] -> Display Network Connection')

        options_button = tk.Button(menuFrame, image=main_properties_image_icon, command=self.popup_options, height=15, width=15)
        options_button.pack(side=tk.LEFT)
        ToolTip(options_button, 'Program Properties')
        ttk.Label(menuFrame, text='  -  ').pack(side=tk.LEFT)

        volself.search_exp_image = tk.PhotoImage(data=EXP_SEARCH_ICON)
        volself.search_exp_image_icon = volself.search_exp_image.subsample(8, 8)

        # Status bar
        int_var = tk.IntVar()
        int_var.set(0)
        self.loading_button = ttk.Progressbar(menuFrame, variable=int_var, orient=tk.HORIZONTAL, length=55, mode="determinate")
        self.loading_button.int_var = int_var
        self.loading_button.s = s
        self.loading_button.pack(side=tk.LEFT)
        LoadingButton(menuFrame, root, self.loading_button)
        ToolTip(self.loading_button, 'Display running jobs (by this program/by you)')
        ttk.Label(menuFrame, text='  +  ').pack(side=tk.LEFT)

        about_button = tk.Button(menuFrame, image=smaller_image, command=self.about, height=15, width=15)
        about_button.pack(side=tk.LEFT)
        ToolTip(about_button, 'About')
        investigation_tip = ttk.Label(menuFrame, text='\tGood Luck And Have Fun In Your Analysis\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t ')
        ToolTip(investigation_tip, random.choice(TIP_LIST))
        investigation_tip.pack(side=tk.LEFT, fill='x')


        menuFrame.pack(anchor="nw")
        self.NoteBook.pack(fill=BOTH, expand=1)

        # Create the table inside the panned windows.
        treetable.pack(side=TOP, fill=BOTH)
        self.pw.add(treetable)
        self.pw.pack(side=TOP, fill=BOTH)
        self.NoteBook.add(self.pw, text='Processes')

        # Check if we already have the modules.
        if process_dlls.has_key(4):
            modev_data = [(item[item.rfind('\\')+1:], item) + ((process_bases[4]['dlls'][item[item.rfind('\\')+1:]], process_bases[4]['ldr'][item[item.rfind('\\')+1:]]) if process_bases[4]['dlls'].has_key(item[item.rfind('\\')+1:]) else (-1, -1)) for item in process_dlls[4]]
        else:
            modev_data = []

        # Create the module tab
        self.modules_table = Modules(self.NoteBook, jmp_pid_index=1, jmp_pid=4,
                                       headers=("Name", "Path", " Dll Base", "LDR Address"),
                                       data=modev_data, resize=True)
        self.frames['Modules'] = self.modules_table
        self.modules_table.pack(side=TOP, fill=BOTH)
        self.NoteBook.add(self.modules_table, text='Modules')
        done_run['process_bases'] = dict(process_bases)# nop
        done_run['process_token'] = dict(process_token)


        # If we have service_dict(run from saved file, else we add it later[when we get the connection).
        # this happend only if we have pycrypto installed (dependency of svcscan).
        if has_crypto:
            data = []
            for pid in service_dict:
                data += service_dict[pid]
            self.service_table = NBTab(self.NoteBook,jmp_pid_index=1, index_pid=3,headers=('offset','order','start','pid','service name','display name','type','state','binary'), data=data, resize=True)
            self.frames['Services'] = self.service_table
            self.service_table.pack(side=TOP, fill=BOTH)
            self.NoteBook.add(self.service_table, text='Services')

        # If we have process_connection(run from saved file, else we add it later[when we get the connection).
        data = []
        for proc in process_connections:
            data += process_connections[proc]
        self.network_table = NBTab(self.NoteBook,jmp_pid_index=1, index_pid=0,
                                  headers=("Pid", "Protocol", "Local Address", "Remote Address", "State", "Created", "Offset"),
                                  data=data, resize=True)
        self.frames['Network'] = self.network_table
        self.network_table.pack(side=TOP, fill=BOTH)
        self.NoteBook.add(self.network_table, text='Network')

        #region allThreads

        # Check if not cached
        #not process_security.values()[len(process_security) - 1].has_key('Groups')
        if (len(process_security) == 0 or any(not gnt.has_key('Groups') for gnt in process_security.values()) or any('Searching...' in gn for gnt in process_security.values() for gn in gnt['Groups'])):

            # Colored the registry menu.
            view_menu_bar.entryconfig(2, background='red')
            subview_menu_bar.entryconfig(0, background='red')

            # Get sid conf and start update table all function.
            t1 = threading.Thread(target=self.update_table_all, name='update_table_all')
            t1.daemon = True
            self.threads.append(t1)
        else:

            # Start the thread to search for registry keys
            t9 = threading.Thread(target=self.registry_keys, name='registry_keys')
            t9.daemon = True
            self.threads.append(t9)

        # Check if not cached and version > xp
        if len(process_connections) == 0: # and int(self.kaddr_space.profile.metadata.get('major')) > 5:

            # Colored the connection menu.
            subview_menu_bar.entryconfig(7, background='red')

            # Start the thread that walk and update this connections to the GUI.
            t4 = threading.Thread(target=self.update_connections, name='update_connections')
            t4.daemon = True
            self.threads.append(t4)

        # Check if not chached and we have pycrypto module installed
        if has_crypto and len(service_dict) == 0:

            # Colored the services menu.
            view_menu_bar.entryconfig(7, background='red')
            subview_menu_bar.entryconfig(8, background='red')

            # Start the thread that walk and update this services to the GUI.
            t3 = threading.Thread(target=self.svc_scan, name='svc_scan')
            t3.daemon = True
            self.threads.append(t3)

        # Start the thread that update the properties (enironment variables and imports).
        t2 = threading.Thread(target=self.update_properties, name='update_properties')
        t2.daemon = True
        self.threads.append(t2)

        # Check if not chached
        if len(mft_explorer) == 0:

            # Colored the MFT menu.
            view_menu_bar.entryconfig(3, background='red')
            subview_menu_bar.entryconfig(1, background='red')

            # Start the threads that call mftparsergui plugin to get the mft from memory
            t5 = threading.Thread(target=self.mft_parser, name='mft_parser')
            t5.daemon = True
            self.threads.append(t5)

        # Check if not chached
        if len(files_scan) == 0:

            # Colored the filesscan menu.
            view_menu_bar.entryconfig(4, background='red')
            subview_menu_bar.entryconfig(2, background='red')

            # Start the thread that call the filescangui plugin to scan the memory for files
            t6 = threading.Thread(target=self.file_scan, name='file_scan')
            t6.daemon = True
            self.threads.append(t6)

        # Check if not chached
        if len(winobj_dict) == 0 and has_winobj:

            # Colored the winobj menu.
            view_menu_bar.entryconfig(5, background='red')
            subview_menu_bar.entryconfig(3, background='red')

            # Starts the thread that call the winobjgui plugin to enumerate all the objects in memory
            t7 = threading.Thread(target=self.win_obj, name='winobj_calc')
            t7.daemon = True
            self.threads.append(t7)

        # Create the update alwayes thread
        if self.is_memtriage:
            ans = messagebox.askquestion("Memtriage Update Data", "Do you want to update the processes data in real time\nNotice! this is an unstable beta version (don't be worry the program will not could crush)")
            if ans == 'yes':
                t11 = threading.Thread(target=self.memtriage_update, name='memtriage_update_process_info_thread')
                t11.daemon = True
                self.threads.append(t11)

        # To add (generic memory information)
        # pfn_conf = conf.ConfObject()
        # # Define conf
        # pfn_conf.remove_option('SAVED-FILE')
        # pfn_conf.readonly = {}
        # pfn_conf.PROFILE = self._config.PROFILE
        # pfn_conf.LOCATION = self._config.LOCATION
        # pfn_conf.kaddr_space = utils.load_as(properties_conf)
        # t8 = threading.Thread(target=self.update_pfn_stuff, args=(pfn_conf,), name='pfn_stuff')
        # t8.daemon = True
        # self.threads.append(t8)

        # Check if not cached
        if len(process_handles) == 0 and done_run.has_key('process_handles'):
            t10 = threading.Thread(target=self.get_all_handles, name='handles')
            t10.daemon = True
            self.threads.append(t10)

        # Starting all the threads
        for c_t in self.threads:
            print '[+] starting Thread:{}'.format(c_t.name)
            c_t.start()

        #endregion allThreads




        # Bind all the main tab short cuts.
        root.bind('<Control-m>', self.control_m)
        root.bind('<Control-M>', self.control_m)
        root.bind('<Control-e>', self.control_e)
        root.bind('<Control-E>', self.control_e)
        root.bind('<Control-r>', self.control_r)
        root.bind('<Control-R>', self.control_r)
        root.bind('<Control-t>', self.control_t)
        root.bind('<Control-T>', self.control_t)
        root.bind('<Control-i>', self.control_i)
        root.bind('<Control-I>', self.control_i)
        root.bind('<Control-v>', self.control_v)
        root.bind('<Control-V>', self.control_v)
        root.bind('<Control-s>', self.control_s)
        root.bind('<Control-S>', self.control_s)
        root.bind('<Control-P>', self.control_p)
        root.bind('<Control-p>', self.control_p)
        root.bind('<Control-W>', self.control_w)
        root.bind('<Control-w>', self.control_w)
        root.bind('<Control-o>', self.popup_options)
        root.bind('<Control-O>', self.popup_options)
        root.bind('<Control-a>', self.view_comments)
        root.bind('<Control-A>', self.view_comments)
        root.bind('<F11>', self.control_h)
        root.bind('<F1>', self.control_h)

        # Stop the load screen (if there any)
        if hasattr(root, 'subprocess'):
            loading_end(root.subprocess)

        # Print our logo
        print AC_LOGO

        # Add the icon image
        self.img = tk.PhotoImage(data=ICON)
        root.tk.call('wm', 'iconphoto', root._w, "-default", self.img)
        root.resizable(True, True)

        # My implemantion of root.mainloop() (to make tkinter "thread safe")
        vol_debug = open(os.path.join(os.path.split(self._vol_path)[0], 'volexp_debug.log'), 'wb')
        vol_debug.write('{}\nStart New -->'.format('-'*80))
        self._run_main_loop = True
        while self._run_main_loop:
            root.update()
            root.update_idletasks()

            # If there is function in the Queue then run it.
            if queue.empty():
                time.sleep(0.1)
            else:
                func, args = queue.get()
                vol_debug.write('{} -> {} ({})\n'.format(time.ctime(), func, args))
                if len(args) > 0:

                    # Get kwargs also in the args (if the last args is tuple ('**kwargs', dict)
                    if type(args[-1]) is tuple and args[-1][0] == '**kwargs':

                        # Check if there is also *args or only **kwargs
                        if len(args) > 1:
                            func(*args[:-1], **args[-1][1])
                        else:
                            func(**args[-1][1])
                    else:
                        func(*args)
                else:
                    func()

        # Kill the program if the user exit.
        root.destroy()
        os._exit(1)
        sys.exit()

    def render_json(self, outfd, data):
        '''
        Memtriage support
        :param outfd: writer (stringio)
        :param data: the data as iterator (calculate())
        :return: Never return (mainloop inside render_text)
        '''
        self.render_text(outfd, data)
        print '[<3] Hope you find what you need bye bye'
        sys.exit(1)

class StructAnalyze(common.AbstractWindowsCommand):
    """Analyze an object (Gui)."""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('STRUCT', short_option='S', default="_EPROCESS", help='The Struct Type')
        config.add_option("ADDR", short_option="A", help="The Address Of The Struct")

        # By Default we check everytime if the struct is_valid and if not we try to recreate it using vm=physical layer, native_vm=kernel_address_space.
        # If the PID options == Physical than we will create it automaticly using vm=physical (and if that fails vm=physical layer, native_vm=kernel_address_space)
        config.add_option("PID", short_option="P", default=4,help="The PID of The process that contains the Struct (if this is not a kernel object)\nPhysical for physical address space (vm and native_vm)")

        # Handle User Input.
        self.kaddr_space = utils.load_as(self._config)
        if (not config.PID) or str(config.PID).lower() != "physical":
            if config.PID and config.PID != 4:
                for task in tasks.pslist(self.kaddr_space):
                    if int(task.UniqueProcessId) == int(config.PID):
                        print '[!] Struct Analyze run on with address space of: {} ({})'.format(str(task.ImageFileName), int(task.UniqueProcessId))
                        self.kaddr_space = task.get_process_address_space()
                        if (not config.ADDR) and ((not config.STRUCT) or config.STRUCT.lower() == "_eprocess"):
                            config.ADDR = str(task.v())
                            config.STRUCT = "_EPROCESS"
                        break

            # Start default struct analyze in the kdbg struct
            elif not config.ADDR:
                config.ADDR = str(win32.tasks.get_kdbg(self.kaddr_space).v())
                if "x64" in config.profile:
                    config.STRUCT = "_KDDEBUGGER_DATA64"
                elif "x86" in config.profile:
                    config.STRUCT = "_KDDEBUGGER_DATA32"

        elif config.PID and str(config.PID).lower() == "physical":
            print '[!] Struct analyze on physical layer.'
            self.kaddr_space = self.kaddr_space.physical_layer()

        # If the ADDR is hexa set it to int.
        if config.ADDR and not isinstance(config.ADDR, int) and config.ADDR.startswith("0x"):
            config.ADDR = int(config.ADDR, 16)

        self._config = config
        self.struct_dict = {}

    def parser(self, struct, t, maxim, s, c_dict, check_functions=True):
        """
        gets the struct,
        the tab - (0) (if you want to print the object in tree style) / recursive count as well,
        the recursive level (maxim),
        the list (c_dict),
        the struct name (s)

        return nothing.

        this function parsing the object and update the list of objects per process
        """

        # Return if we done.
        if t == maxim:
            return

        # Go all over the functions inside the class (if this struct is a class)
        if check_functions and isinstance(struct, obj.CType):
            for func_name  in dir(struct):#get_functions(struct):
                if func_name[0] != '_' and callable(getattr(struct, func_name)):
                    c_dict[func_name] = {'|properties|': ('>---Volatility---<', '>---Function---<', 'Function')}

        # loop to parse the current members of the object
        for m in struct.members:

            val = eval("struct.{}".format(m))
            obj_type = eval("struct.{}.obj_type".format(m))
            obj_offset = eval("struct.{}.obj_offset".format(m))
            c_dict[m] = {'|properties|': (val, obj_offset, str(obj_type))} #struct.v() "{}.{}".format(s, m)

            # check if the members has more members
            try:
                st = val.members # To fail here and not in inside the self.parser
                s2 = str(s + ".{}".format(m.strip()))[str(s + ".{}".format(m.strip())).index('.') + 1:]
                self.parser(val, t + 1, maxim, s2, c_dict[m])

            except Exception:
                pass

    def get_se_frame(self, master, writeSupport=True):
        '''
        This pack the StructExplorer to the master frame
        :param master: frame to pack the StructExplorer inside.
        :param writeSupport: Flag if to enable write support to the image.
        :return: None
        '''
        StructExplorer(master, self.struct_dict, self, headers=("Struct Name", "Member Value", "Struct Address", "Object Type"), searchTitle='Struct Analayzer Search (deeg 3 inside)', writeSupport=writeSupport, relate=master).pack(fill=BOTH, expand=YES)

    def calculate(self):
        '''
        This function parse the struct object with his child objects
        :return: None
        '''
        struct = obj.Object(self._config.STRUCT, self._config.ADDR, self.kaddr_space)

        # Check if this struct specified address is in the physical layer (usually came from scan plugin that scan the physical layer)
        if not struct or not struct.is_valid():
            struct = obj.Object(self._config.STRUCT, self._config.ADDR, self.kaddr_space.physical_space(), native_vm=self.kaddr_space)
            if not struct or not struct.is_valid():
                struct = obj.Object(self._config.STRUCT, self._config.ADDR, self.kaddr_space)
            else:
                self.kaddr_space = self.kaddr_space

        try:
            self.parser(struct, 0, 3, self._config.STRUCT, self.struct_dict)
        except Exception:
            raise Exception('[-] unable to parse this object (addr: {}, type: {}), is_valid:{}'.format(self._config.ADDR, self._config.STRUCT, struct.is_valid()))

    def render_text(self, outfd, data):
        '''
        This function start the StructExplorer with the data from self.calculate
        :param outfd: writer
        :param data: calculate()
        :return: None
        '''
        global volself
        global root
        job_queue.put_alert = job_queue.put
        outfd.write("GL & HF <3")
        root = Tk()
        volself = self
        volself.search_exp_image = tk.PhotoImage(data=EXP_SEARCH_ICON)
        volself.search_exp_image_icon = volself.search_exp_image.subsample(8, 8)
        self.img = tk.PhotoImage(data=ICON)
        root.tk.call('wm', 'iconphoto', root._w, "-default", self.img)
        if hasattr(self._config, 'WRITE') and self._config.WRITE:
            flag = True
        else:
            flag = False
        self.get_se_frame(root, flag)
        root.title("Struct Analayzer {} ({})".format(self._config.STRUCT, self._config.ADDR))
        root.geometry("950x450")

        # Exit Popup
        def on_exit(none=None):
            '''
            Exit popup
            :param none: None (support event)
            :return: None
            '''
            if messagebox.askokcancel("Quit",
                                      "Do you really wish to quit?"):
                self._run_main_loop = False
        root.protocol("WM_DELETE_WINDOW", on_exit)

        self._run_main_loop = True

        # mainloop
        while self._run_main_loop:
            root.update()
            root.update_idletasks()

            # If there is function in the Queue then run it.
            if queue.empty():
                time.sleep(0.1)
            else:
                func, args = queue.get()
                if len(args) > 0:

                    # Get kwargs also in the args (if the last args is tuple ('**kwargs', dict)
                    if type(args[-1]) is tuple and args[-1][0] == '**kwargs':

                        # Check if there is also *args or only **kwargs
                        if len(args) > 1:
                            func(*args[:-1], **args[-1][1])
                        else:
                            func(**args[-1][1])
                    else:
                        func(*args)
                else:
                    func()

    def write(self, object, data):
        '''
        Write Data to an object in the memory
        :param object: The object
        :param data: The new data
        :return: None
        '''
        object.write(data)

    def render_json(self, outfd, data):
        '''
        Memtriage support
        :param outfd: writer (stringio)
        :param data: the data as iterator (calculate())
        :return: Never return (mainloop inside render_text)
        '''
        self.render_text(outfd, data)
        print '[<3] Hope you find what you need bye bye'
        sys.exit(1)

class WinObjGui(common.AbstractWindowsCommand):
    """WinObj (Explorer GUI plugin)"""
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('GET_DICT', short_option='M', default='no', cache_invalidator=False,
                          help='print the dictionary(no gui)')
        self.kaddr_space = utils.load_as(self._config)
        self._config = config

    def winobj_builder(self, winobj_calc, c_winobj_dict, path_list, info, full_path_str):
        '''
        This function build the winobj tree
        :param winobj_calc: winobj.calclulate()
        :param c_winobj_dict: the dict pointer to build inside
        :param path_list: the current list of path (when its empty we put ower item)
        :param info: object information
        :param full_path_str: full path
        :return: None
        '''
        global winobj_dict

        # Go inside the path list to find the father of this object and put this object as his son.
        if len(path_list) > 0:

            value = path_list.pop(0)
            value = value if value != '' else ' '  # Rename Empty name in memory to space.
            if c_winobj_dict.has_key(value):
                self.winobj_builder(winobj_calc, c_winobj_dict[value], path_list, info, full_path_str)
            else:
                c_winobj_dict[value] = {}
                self.winobj_builder(winobj_calc, c_winobj_dict[value], path_list, info, full_path_str)


        else:
            # Add the information
            c_winobj_dict["|properties|"] = info

            # If this object is directory search if he have child object.
            if info[0] == 'Directory':
                try:
                    if full_path_str.startswith('//'):
                        return
                    winobj_calc.SaveByPath(full_path_str, self.kaddr_space)
                except Exception as ex:
                    print ex
                    return

                # Go deep inside the directory and find more objects
                l = winobj_calc.tables[full_path_str][winobj_calc.VALUES]
                for obj in l:
                    info = (

                        obj[winobj_calc.HEADER].get_object_type(),
                        obj[winobj_calc.ADDITIONAL_INFO],
                        str(obj[winobj_calc.ADDR]))
                    if c_winobj_dict.has_key(obj[winobj_calc.NAME]):
                        if self._config.verbose:
                            print '[+] already have object', obj[winobj_calc.NAME]
                        continue

                    new_path_list = []
                    full_path_str = '{}/{}'.format(full_path_str, obj[winobj_calc.NAME])
                    if self._config.verbose:
                        print '[+] Real Serach for {}'.format(full_path_str)
                    if not c_winobj_dict.has_key(obj[winobj_calc.NAME]):
                        c_winobj_dict[obj[winobj_calc.NAME]] = {'|properties|': info}
                    self.winobj_builder(winobj_calc, c_winobj_dict[obj[winobj_calc.NAME]], new_path_list, info,
                                        full_path_str)

    def win_obj(self, winobj_calc, winobj_dict):
        '''
        This function start the winob_builder with the right parameters.
        :param winobj_calc: winobj calculate
        :param winobj_dict: the db dict
        :return: None
        '''
        # __init__ importent from winobj plugin.
        winobj_calc.NAME = 0x1
        winobj_calc.ADDR = 0x0
        winobj_calc.HEADER = 0x2
        winobj_calc.VALUES = 0x1
        winobj_calc.ADDITIONAL_INFO = 0x3

        winobj_calc.POINTER_SIZE = 0x8
        winobj_calc.OBJECT_HEADER_QUOTA_INFO_SIZE = 0x20
        winobj_calc.OBJECT_HEADER_PROCESS_INFO_SIZE = 0x10
        winobj_calc.OBJECT_HEADER_HANDLE_INFO_SIZE = 0x10
        winobj_calc.OBJECT_HEADER_NAME_INFO_SIZE = 0x20
        winobj_calc.OBJECT_HEADER_CREATOR_INFO_SIZE = 0x20
        winobj_calc.OBJECT_HEADER_NAME_INFO_ID = 0x2
        winobj_calc.OBJECT_HEADER_CREATOR_INFO_ID = 0x1
        winobj_calc.OBJECT_HEADER_HANDLE_INFO_ID = 0x4
        winobj_calc.OBJECT_HEADER_QUOTA_INFO_ID = 0x8
        winobj_calc.OBJECT_HEADER_PROCESS_INFO_ID = 0x10
        winobj_calc.OBJECT_HEADER_SIZE = 0x30
        winobj_calc.OBJECT_POOL_HEADER = 0x10
        winobj_calc.OBJECT_INFO_HEADERS_LIST = [winobj_calc.OBJECT_HEADER_CREATOR_INFO_ID,
                                                winobj_calc.OBJECT_HEADER_HANDLE_INFO_ID,
                                                winobj_calc.OBJECT_HEADER_QUOTA_INFO_ID,
                                                winobj_calc.OBJECT_HEADER_NAME_INFO_ID,
                                                winobj_calc.OBJECT_HEADER_PROCESS_INFO_ID]

        winobj_calc.OBJECT_INFO_HEADERS_ID_TO_SIZE = {
            winobj_calc.OBJECT_HEADER_NAME_INFO_ID: winobj_calc.OBJECT_HEADER_NAME_INFO_SIZE,
            winobj_calc.OBJECT_HEADER_CREATOR_INFO_ID: winobj_calc.OBJECT_HEADER_CREATOR_INFO_SIZE,
            winobj_calc.OBJECT_HEADER_HANDLE_INFO_ID: winobj_calc.OBJECT_HEADER_HANDLE_INFO_SIZE,
            winobj_calc.OBJECT_HEADER_QUOTA_INFO_ID: winobj_calc.OBJECT_HEADER_QUOTA_INFO_SIZE,
            winobj_calc.OBJECT_HEADER_PROCESS_INFO_ID: winobj_calc.OBJECT_HEADER_PROCESS_INFO_SIZE}

        winobj_calc.tables = {}
        winobj_calc.root_obj_list = []
        winobj_calc.update_sizes(self.kaddr_space)
        kdbg = tasks.get_kdbg(self.kaddr_space)
        root_dir = winobj_calc.get_root_directory(kdbg, self.kaddr_space)
        winobj_calc.parse_directory(root_dir, self.kaddr_space, winobj_calc.root_obj_list)
        winobj_calc.tables["/"] = (root_dir, winobj_calc.root_obj_list)
        winobj_calc.get_directory(self.kaddr_space)

        # Go all over the tables and build them.
        for table in list(winobj_calc.tables.keys()):
            l = winobj_calc.tables[table][winobj_calc.VALUES]
            for obj in l:
                info = (
                    # obj[winobj_calc.NAME],
                    obj[winobj_calc.HEADER].get_object_type(),
                    obj[winobj_calc.ADDITIONAL_INFO],
                    str(obj[winobj_calc.ADDR]))
                full_path_str = '{}/{}'.format(table, obj[winobj_calc.NAME])
                if table == '/':
                    self.winobj_builder(winobj_calc, winobj_dict, [table, obj[winobj_calc.NAME]], info, full_path_str)
                else:
                    if self._config.verbose:
                        print 'create /{} directory'.format(full_path_str)
                    self.winobj_builder(winobj_calc, winobj_dict, ['/', table, obj[winobj_calc.NAME]], info,
                                        '/{}'.format(full_path_str))

    def calculate(self):
        '''
        The Calculate function that cal win_obj function,
        This function return error if winobj is not in the machine.
        :return: None
        '''
        if not has_winobj:
            debug.error('Please download winobj.py plugin (from the kslgroup github)')
        winobj_calc = winobj.WinObj(self._config)
        self.win_obj(winobj_calc, winobj_dict)

        # If we only want the db dict (like volexp plugin).
        if self._config.GET_DICT and self._config.GET_DICT != 'no' and self._config.GET_DICT != 'None':
            with open(self._config.GET_DICT, 'wb') as my_file:
                pickle.dump(winobj_dict, my_file)
            sys.exit(1)
        return

    def render_json(self, outfd, data):
        '''
        Memtriage support
        :param outfd: writer (stringio)
        :param data: the data as iterator (calculate())
        :return: Never return (mainloop inside render_text)
        '''
        self.render_text(outfd, data)
        print '[<3] Hope you find what you need bye bye'
        sys.exit(1)

    def render_text(self, outfd, data):
        global volself
        global root

        if self._config.GET_DICT == 'no' or not self._config.GET_DICT or self._config.GET_DICT == 'None':
            job_queue.put_alert = job_queue.put
            outfd.write("GL & HF <3")
            app = Tk()
            volself = self
            volself.search_exp_image = tk.PhotoImage(data=EXP_SEARCH_ICON)
            volself.search_exp_image_icon = volself.search_exp_image.subsample(8, 8)
            self.img = tk.PhotoImage(data=ICON)
            app.tk.call('wm', 'iconphoto', app._w, "-default", self.img)
            WinObjExplorer(app, winobj_dict, resize=False, relate=app).pack(fill=BOTH, expand=YES)
            app.title("WinObj Explorer(Shachaf Atun[KslGroup])")
            app.geometry("700x450")
            root = app

            # Exit Popup
            def on_exit(none=None):
                '''
                Exit popup
                :param none: None (support event)
                :return: None
                '''
                if messagebox.askokcancel("Quit",
                                          "Do you really wish to quit?"):
                    self._run_main_loop = False

            root.protocol("WM_DELETE_WINDOW", on_exit)

            self._run_main_loop = True

            # mainloop
            while self._run_main_loop:
                root.update()
                root.update_idletasks()

                # If there is function in the Queue then run it.
                if queue.empty():
                    time.sleep(0.1)
                else:
                    func, args = queue.get()
                    if len(args) > 0:

                        # Get kwargs also in the args (if the last args is tuple ('**kwargs', dict)
                        if type(args[-1]) is tuple and args[-1][0] == '**kwargs':

                            # Check if there is also *args or only **kwargs
                            if len(args) > 1:
                                func(*args[:-1], **args[-1][1])
                            else:
                                func(**args[-1][1])
                        else:
                            func(*args)
                    else:
                        func()

class MftParserGui(common.AbstractWindowsCommand):
    """MftParser (Explorer GUI plugin)"""
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('GET_DICT', short_option='M', default='no', cache_invalidator=False,
                          help='print the dictionary(no gui)')
        self.kaddr_space = utils.load_as(self._config)
        self._config = config

    def mft_recurse_builder(self, c_dict, path_list, data):
        global mft_explorer

        # Go inside the path list to find the father of this object and put this object as his son.
        if len(path_list) > 0:
            value = path_list.pop(0)
            value = value if value != '' else ' '  # Rename Empty name in memory to space.
            if c_dict.has_key(value):
                self.mft_recurse_builder(c_dict[value], path_list, data)
            else:
                c_dict[value] = {}
                self.mft_recurse_builder(c_dict[value], path_list, data)
        else:
            c_dict["|properties|"] = data

    def mft_parser(self, parser):
        global mft_explorer
        for offset, mft_entry, attributes in parser:
            if len(attributes) == 0:
                continue
            for a, i in attributes:
                if i == None:
                    continue
                if a.startswith("FILE_NAME"):
                    if hasattr(i, "ParentDirectory"):
                        full = unicode(mft_entry.get_full_path(i), errors='replace')
                        path_list = full.split("\\")
                        if len(path_list) > 0:
                            output = i.get_full(full)
                            creation = output[:28]
                            modified = output[29:57]
                            mft_alerted = output[59:88]
                            access = output[90:119]
                            tup = mft_entry.get_mft_type().split("&")
                            if len(tup) == 2:
                                mft_use, mft_type = tup[0], tup[1]
                            else:
                                mft_use = "NOP"
                                mft_type = "File"
                            data = (
                            creation, modified, mft_alerted, access, mft_use, mft_type, int(mft_entry.LinkCount),
                            int(mft_entry.RecordNumber), offset)

                            # Create the Dos No Path Folder:
                            if len(path_list) == 1 and '~' in path_list[0]:
                                path_list = ['Dos No Path Folder(Created By VolExp!)', path_list[0]]
                            elif len(path_list) == 1:
                                path_list = ['No Path Folder(Created By VolExp!)', path_list[0]]

                            self.mft_recurse_builder(mft_explorer, path_list, data)

    def calculate(self):
        parser = mftparser.MFTParser(self._config).calculate()
        self.mft_parser(parser)

        # If we only want the db dict (like volexp plugin).
        if self._config.GET_DICT and self._config.GET_DICT != 'no' and self._config.GET_DICT != 'None':
            with open(self._config.GET_DICT, 'wb') as my_file:
                pickle.dump(mft_explorer, my_file)
            sys.exit(1)
        return

    def render_json(self, outfd, data):
        '''
        Memtriage support
        :param outfd: writer (stringio)
        :param data: the data as iterator (calculate())
        :return: Never return (mainloop inside render_text)
        '''
        self.render_text(outfd, data)
        print '[<3] Hope you find what you need bye bye'
        sys.exit(1)

    def render_text(self, outfd, data):
        global volself

        if self._config.GET_DICT == 'no' or not self._config.GET_DICT or self._config.GET_DICT == 'None':
            outfd.write("GL & HF <3")
            app = Tk()
            volself = self
            volself.search_exp_image = tk.PhotoImage(data=EXP_SEARCH_ICON)
            volself.search_exp_image_icon = volself.search_exp_image.subsample(8, 8)
            self.img = tk.PhotoImage(data=ICON)
            app.tk.call('wm', 'iconphoto', app._w, "-default", self.img)
            Explorer(app, my_dict=mft_explorer, headers=("File Name", "Creation", "Modified", "MFT alerted", "Access", "Use", "Type", "Link count", "Record number", "Offset"), searchTitle='Search Form MFT Records', relate=app).pack(fill=BOTH, expand=YES)
            app.geometry("700x450")
            app.title("MFT Explorer")
            app.mainloop()

class FileScanGui(common.AbstractWindowsCommand):
    """FileScan (Explorer GUI plugin)"""
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('DUMP-DIR', short_option='D', default=None, cache_invalidator=False,
                          help='Directory in which to dump executable files')
        config.add_option('GET_DICT', short_option='M', default='no', cache_invalidator=False,
                          help='print the dictionary(no gui)')
        self.kaddr_space = utils.load_as(self._config)
        self._config = config

    def file_scan_builder(self, c_dict, path_list, data):
        '''
        Build the file scan database dictionary.
        :param c_dict: current db
        :param path_list: the path to the file
        :param data: data of the file (|properties|)
        :return: None
        '''
        global files_scan

        if len(path_list) > 0:
            value = path_list.pop(0)
            value = value if value != '' else ' ' # Rename Empty name in memory to space.
            if c_dict.has_key(value):
                self.file_scan_builder(c_dict[value], path_list, data)
            else:
                c_dict[value] = {}
                self.file_scan_builder(c_dict[value], path_list, data)
        else:
            c_dict["|properties|"] = data

    def file_scan(self, files):
        '''
        Call the file scan builder with the right arguments (data and path to the file)
        :param files: filescan calc
        :return: None
        '''
        global files_scan

        # Get all the data from the filescan plugin and build the tree using file_scan_builder function
        for file in files:
            header = file.get_object_header()
            file_path = unicode(file.file_name_with_device(), errors='ignore')
            if file_path:
                path_list = file_path.split("\\")
                file_type = file_path.split('.')
                if len(file_type) > 1:
                    file_type = file_type[-1]
                else:
                    file_type = ''
                data = (file.access_string(), file_type, int(header.PointerCount), int(header.HandleCount), file.obj_offset)
                self.file_scan_builder(files_scan, path_list, data)

    def calculate(self):
        '''
        Calculate methond, use filescan, shimecachemem, userassis, shimcache, amcache.
        :return:
        '''
        global files_scan
        files = filescan.FileScan(self._config).calculate()
        self.file_scan(files)

        files_scan['?shimcachemem?'] = []
        files_scan['?userassist?']   = []
        files_scan['?shimcache?']    = []
        files_scan['?amcache?']      = []

        # All of this modules require crypto.
        if has_crypto:
            if (self.kaddr_space.profile.metadata.get("major"), self.kaddr_space.profile.metadata.get("minor")) != (6, 4):
                # Getting also information about execution program.
                from volatility.plugins.registry import userassist

                # Getting userassist data.
                self._config.HIVE_OFFSET = None
                ua = userassist.UserAssist(self._config)
                userassist.debug.error = lambda e: sys.stderr.write('[-] The requested key could not be found in the hive(s) searched\n')
                calc = ua.calculate()
                userassist_data = [c_data[1] for c_data in ua.generator(calc)]
                files_scan['?userassist?'] = userassist_data

                # Getting shimcache data.
                from volatility.plugins.registry import shimcache
                self._config.HIVE_OFFSET = None
                sc = shimcache.ShimCache(self._config)
                calc = sc.calculate()
                shimcache_data = [c_data[1] for c_data in sc.generator(calc)]
                files_scan['?shimcache?'] = shimcache_data

                # Getting amcache data.
                from volatility.plugins.registry import amcache
                self._config.HIVE_OFFSET = None
                amc = amcache.AmCache(self._config)
                calc = amc.calculate()
                amcache_data = [c_data[1] for c_data in amc.generator(calc)]
                files_scan['?amcache?'] = amcache_data
            else:
                try:
                    from volatility.plugins import shimcachemem
                    has_shimcachemem = True
                except ImportError:
                    try:
                        from volatility.community.plugins import shimcachemem
                        has_shimcachemem = True
                    except ImportError:
                        has_shimcachemem = False

                if has_shimcachemem:
                    self._config.HIVE_OFFSET = None
                    scm = shimcachemem.ShimCacheMem(self._config)
                    calc = scm.calculate()
                    shimcachemem_data = [c_data[1] for c_data in scm.generator(calc)]
                    files_scan['?shimcachemem?'] = shimcachemem_data

        # If we only want the db dict (like volexp plugin).
        if self._config.GET_DICT and self._config.GET_DICT != 'no' and self._config.GET_DICT != 'None':
            with open(self._config.GET_DICT, 'wb') as my_file:
                pickle.dump(files_scan, my_file)
            sys.exit(1)
        return

    def render_json(self, outfd, data):
        '''
        Memtriage support
        :param outfd: writer (stringio)
        :param data: the data as iterator (calculate())
        :return: Never return (mainloop inside render_text)
        '''
        self.render_text(outfd, data)
        print '[<3] Hope you find what you need bye bye'
        sys.exit(1)

    def render_text(self, outfd, data):
        global volself
        global root

        if self._config.GET_DICT == 'no' or not self._config.GET_DICT or self._config.GET_DICT == 'None':
            outfd.write("GL & HF <3")
            app = Tk()
            volself = self
            volself.search_exp_image = tk.PhotoImage(data=EXP_SEARCH_ICON)
            volself.search_exp_image_icon = volself.search_exp_image.subsample(8, 8)
            self.img = tk.PhotoImage(data=ICON)
            app.tk.call('wm', 'iconphoto', app._w, "-default", self.img)
            FileExplorer(app, dict=files_scan, headers=("File Name", "Access", "Type", "Pointer Count", "Handle Count", "Offset"), searchTitle='Search For Files', relate=app).pack(fill=BOTH, expand=YES)
            app.geometry("1400x650")
            app.title("Files Explorer")
            root = app

            # Exit Popup
            def on_exit(none=None):
                '''
                Exit popup
                :param none: None (support event)
                :return: None
                '''
                if messagebox.askokcancel("Quit",
                                          "Do you really wish to quit?"):
                    self._run_main_loop = False

            root.protocol("WM_DELETE_WINDOW", on_exit)

            self._run_main_loop = True

            # mainloop
            while self._run_main_loop:
                root.update()
                root.update_idletasks()

                # If there is function in the Queue then run it.
                if queue.empty():
                    time.sleep(0.1)
                else:
                    func, args = queue.get()
                    if len(args) > 0:

                        # Get kwargs also in the args (if the last args is tuple ('**kwargs', dict)
                        if type(args[-1]) is tuple and args[-1][0] == '**kwargs':

                            # Check if there is also *args or only **kwargs
                            if len(args) > 1:
                                func(*args[:-1], **args[-1][1])
                            else:
                                func(**args[-1][1])
                        else:
                            func(*args)
                    else:
                        func()

class RegistryGui(common.AbstractWindowsCommand):
    """Registry (GUI plugin)"""
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('GET_DICT', short_option='M', default='no', cache_invalidator=False,
                          help='print the dictionary(no gui)')
        self.kaddr_space = utils.load_as(self._config)
        self._config = config

    def order_right(self, dict, path_list, time):
        '''
        This function insert the key in the right place inside the dictionary
        :param dict: some parent dictionary of the key inside the reg_dict
        :param path_list: the key full name in a path list
        :param time: key access time
        :return: None
        '''
        global reg_dict

        # If the path_list is not empty its means that the dictionary is not the dictionary that represent the key information
        if len(path_list) > 0:

            # Some parent of the key.
            value = path_list.pop(0).title()

            # Insert this key to the dictionary (if this key is not already in there).
            if not dict.has_key(value):
                dict[value] = {}

            # Go deep inside untill len(path_list) == 0 that means that the dict represent the current key and we can insert the data to this key.
            self.order_right(dict[value], path_list, time)
        else:
            dict['|properties|'] = time

    def reg_hive_thread_builder(self, hive, user):
        '''
        This function go all over the keys inside this hive and insert them to the reg_dict (using self.order_right funciton)
        :param hive:
        :param user:
        :return:
        '''
        global reg_dict
        global job_queue

        print
        'start regThread with user:{} hive:{}'.format(user, hive)
        reg_conf = conf.ConfObject()
        reg_conf.readonly = {}
        reg_conf.PROFILE = self._config.PROFILE
        reg_conf.LOCATION = self._config.LOCATION
        reg_conf.remove_option('ADDRESS')

        # Get regapi (volatiliry registry api)
        regapi = registryapi.RegistryApi(reg_conf)

        # Go all over the keys for this hive
        for key in regapi.reg_get_all_keys(hive, user):

            # If this hive inside know hives than get his real name.
            for know_hive in KNOWN_HIVES:

                # If this is the hive
                if know_hive in str(key[1]):
                    key = (key[0], str(key[1]).replace(know_hive, KNOWN_HIVES[know_hive]))

            # Get reg path
            reg_path = str(key[1]).replace('\\\\', '\\').split('\\')

            # Send the information for the self.order_right function to insert the data in the right place inside the reg_dict
            self.order_right(reg_dict, reg_path, key[0])

        # done_run['reg_dict'] = reg_dict
        print
        'finish build {} hive'.format(hive)

        # A signal to know that we finish with this hive so if we save this and run this again we will not search for this information again.
        reg_dict['Finish build hives'].append(hive)

    def registry_keys(self):
        '''
        This function send one thread per hive to go all over his key and get theirs name and time stamp.
        :param reg: Regapi (volatility registry api)
        :return: None
        '''
        global reg_dict

        # This function need registryapi from volatility (one of registryapi is pycrypto)
        if not has_crypto:
            return

        # Get volatility registry api
        self.regapi = reg = registryapi.RegistryApi(self._config)
        self.threads = []

        # Set the 'Finish build hives' key for the hives that done rune (support for cache file).
        if not reg_dict.has_key('Finish build hives'):
            reg_dict['Finish build hives'] = []

        # Go all over the hives offset and starts a thread to find all the keys in each hive.
        for offset in reg.all_offsets:
            print
            reg.all_offsets[offset]

            # Reset the current reg hive and user
            reg.reset_current()

            # Find hive name
            hive_path = reg.all_offsets[offset].lower().replace('\\\\', '\\').split('\\')
            hive = hive_path[-1]

            # Check if this hive is well known and if so change his name (for user convenience).
            if KNOWN_HIVES.has_key(hive):
                hive = KNOWN_HIVES[hive]

            # Find user (if this is user hive).
            user = hive_path[4] if reg.all_offsets[offset].lower().find("\\" + "ntuser.dat") != -1 else None
            print 'user {} \t hive:{}'.format(user, hive)

            # Start the thread to get all the keys
            c_thread = threading.Thread(target=self.reg_hive_thread_builder, args=(hive, user))
            self.threads.append(c_thread)
            c_thread.start()

            #self.reg_hive_thread_builder(hive, user)

        # Verify that all the hives founded.
        last_time_count = [0, 0]
        while len(reg.all_offsets) > len(reg_dict):
            time.sleep(3)

            # Return after 30 seconds with the same hives founded
            if last_time_count == len(reg_dict):
                last_time_count[1] += 1
            else:
                last_time_count = [len(reg_dict), 0]

            if last_time_count[1] == 10:
                break

        print
        'done REG_BULD'

    def calculate(self):
        self.registry_keys()

        # If we only want the db dict (like volexp plugin).
        if self._config.GET_DICT and self._config.GET_DICT != 'no' and self._config.GET_DICT != 'None':

            # Wait to get all the data.
            for c_thread in self.threads:
                c_thread.join()
            with open(self._config.GET_DICT, 'wb') as my_file:
                pickle.dump(reg_dict, my_file)
            sys.exit(1)
        return

    def render_json(self, outfd, data):
        '''
        Memtriage support
        :param outfd: writer (stringio)
        :param data: the data as iterator (calculate())
        :return: Never return (mainloop inside render_text)
        '''
        self.render_text(outfd, data)
        print '[<3] Hope you find what you need bye bye'
        sys.exit(1)

    def render_text(self, outfd, data):
        global queue

        if self._config.GET_DICT == 'no' or not self._config.GET_DICT or self._config.GET_DICT == 'None':
            outfd.write("GL & HF <3")
            self.app = app = Tk()
            RegViewer(app, dict=reg_dict, headers=("Key Name", "Creation"), reg_api=self.regapi).pack(fill=BOTH, expand=YES)
            # app = Explorer(my_dict=reg_dict, headers=('reg', 'time'))
            app.title("RegEdit")
            app.geometry("800x500")
            self.img = tk.PhotoImage(data=ICON)
            app.tk.call('wm', 'iconphoto', app._w, "-default", self.img)
            #app.mainloop()
            messagebox.showinfo("Notice", "The registry updates while you view it\nEvery time you collapse or expand, the application will check if there are new keys to display.")
            while True:
                app.update()
                app.update_idletasks()

                # If there is function in the Queue then run it.
                if queue.empty():
                    time.sleep(0.1)
                else:
                    func, args = queue.get()
                    if len(args) > 0:

                        # Get kwargs also in the args (if the last args is tuple ('**kwargs', dict)
                        if type(args[-1]) is tuple and args[-1][0] == '**kwargs':

                            # Check if there is also *args or only **kwargs
                            if len(args) > 1:
                                func(*args[:-1], **args[-1][1])
                            else:
                                func(**args[-1][1])
                        else:
                            func(*args)
                    else:
                        func()


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ['HexDump', 'CmdPlugin', 'LoadScreen']:
        classes_names = {'HexDump':HexDump,
                  'CmdPlugin':CmdPlugin}
        class_name = sys.argv[1]
        if class_name == 'HexDump':
            file_path = sys.argv[2]
            print sys.argv

            # Read the file data and the delete him.
            with open(file_path, 'rb') as f:
                data = pickle.load(f)
            os.remove(file_path)

            app = HexDump(file_name=file_path, file_data=data, row_len=16)
            app.title('{}'.format(sys.argv[3]))
            #app.resizable(False, False)
            window_width = 1050
            window_height = 800
            width = app.winfo_screenwidth()
            height = app.winfo_screenheight()
            app.geometry('%dx%d+%d+%d' % (window_width, window_height, width*0.5-(window_width/2), height*0.5-(window_height/2)))
            app.attributes('-topmost', 1)
            app.attributes('-topmost', 0)
            app.mainloop()

        elif class_name == 'CmdPlugin':
            plugin_name = sys.argv[2]
            vol_path = sys.argv[3]
            plugins_path = sys.argv[4]
            file_path = sys.argv[5]
            profile = sys.argv[6]
            app = CmdPlugin(plugin_name, vol_path, plugins_path, file_path, profile)
            app.title('Volatility shell')
            app.geometry("700x450")
            app.attributes('-topmost', 1)
            app.attributes('-topmost', 0)
            app.mainloop()

        elif class_name == 'LoadScreen':
            loading_reason = sys.argv[2]
            app = Tk()
            img = tk.PhotoImage(data=ICON)
            app.tk.call('wm', 'iconphoto', app._w, "-default", img)
            app.loadscreen = LoadingScreen(app)
            app.resizable(False, False)
            app.title("Load Screen, Please Wait({})".format(loading_reason))
            app.mainloop()

    # Run the portable
    else:
        global my_arguments
        global popapp
        import argparse
        global root
        def set_options(dictionary):
            global my_arguments
            my_arguments = dictionary
            popapp.destroy()

        parser = argparse.ArgumentParser(description='VolExp')
        parser.add_argument('-f', '--file', help='Memory file path.')
        parser.add_argument('-p', '--profile', help='Memory file profile.')
        parser.add_argument('-d', '--dump', help='Dump directory')
        parser.add_argument('-s', '--saved', help='Open saved file (.atz exstantion).')
        parser.add_argument('-k', '--kdbg', help='KDBG address (make it faster).')
        parser.add_argument('-v', '--volatility', help=r'Volatility file path(volatility.exe\vol.py \ memtriage)')
        parser.add_argument('-a', '--apikey', help='Virus Total API Key to support upload and check hashes using virus total db')
        args = parser.parse_args()

        import volatility.registry as registry
        registry.PluginImporter()
        config = conf.ConfObject()
        config._portable = True
        import volatility.addrspace as addrspace
        registry.register_global_options(config, commands.Command)
        registry.register_global_options(config, addrspace.BaseAddressSpace)

        args_dict = vars(args)
        options = {'Saved File': args_dict['saved'],
        'Memory File': args_dict['file'],
        'Memory Profile': args_dict['profile'],
        'Dump-Dir': args_dict['dump'],
        'KDBG Address (for faster loading)': args_dict['kdbg'],
        #'Show Unnamed Handles': args_dict[''],
        'Volatility File Path': args_dict['volatility'],
        'Virus Total API Key': args_dict['apikey']}

        # Fileter None values(values not from user input)
        filtered = {k: v for k, v in options.items() if v is not None}
        options.clear()
        options.update(filtered)

        root = Tk()
        img = tk.PhotoImage(data=ICON)
        root.tk.call('wm', 'iconphoto', root._w, "-default", img)
        app = Options(root, options, True)
        x = root.winfo_x()
        y = root.winfo_y()
        root.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
        root.after(1000, app.Save)
        root.title('Options')
        while root.title() == "Options":
            root.update()
            root.update_idletasks()
            time.sleep(0.2)

        root.loadscreen = 'LoadingScreen(root)'
        options = app.user_dict
        #root.withdraw()
        root.subprocess = loading_start('Initial VolExp')
        root.update()
        root.update_idletasks()

        # From Saved File
        if options.has_key('Saved File') and options['Saved File'].endswith('atz'):
            with open(options['Saved File'], 'rb') as handle:
                saved_data = pickle.load(handle)

            file_path = saved_data['file_path']
            dump_dir = saved_data['dump_dir']
            profile = saved_data['profile']
            api_key = saved_data['api_key'] if saved_data.has_key("api_key") else ""
            vol_path = saved_data['vol_path']

            config.SAVED_FILE = options['Saved File']
            config.LOCATION = config.location = r"{}".format(file_path)
            config.opts['location'] = str(config.LOCATION)
            config.PROFILE = config.profile = profile
            config.opts['profile'] = str(config.PROFILE)
            config.DUMP_DIR = str(dump_dir)
            config.opts['dump_dir'] = str(config.DUMP_DIR)  # tofix unable to load it good.
            config.API_KEY = str(api_key)
            config.opts['api_key'] = str(config.API_KEY)
            config.VOL_PATH = str(vol_path)
            config.opts['vol_path'] = str(vol_path)

            my_ve = VolExp(config, False)
            my_ve._vol_path = saved_data['vol_path']
            ve_calc = my_ve.load(options['Saved File'])
            my_ve.render_text(None, ve_calc, root)

        # Run new
        else:
            my_arguments = options
            config.LOCATION = config.location = r"file://{}".format(my_arguments['Memory File'])
            config.opts['location'] = str(config.LOCATION)
            config.PROFILE = config.profile = my_arguments['Memory Profile']
            config.opts['profile'] = str(config.PROFILE)
            config.DUMP_DIR = my_arguments['Dump-Dir']
            config.opts['dump_dir'] = str(config.DUMP_DIR)
            config.API_KEY = my_arguments['Virus Total API Key']
            config.opts['api_key'] = str(config.API_KEY)
            vol_path = my_arguments['Volatility File Path']
            config.VOL_PATH = str(vol_path)
            config.opts['vol_path'] = str(vol_path)
            config.SAVED_FILE = ""

            location = config.LOCATION
            profile = config.PROFILE
            dump_dir = config.DUMP_DIR
            api_key = config.API_KEY
            vol_path = my_arguments['Volatility File Path']

            done_run['location'] = location
            done_run['profile'] = profile
            done_run['dump_dir'] = dump_dir
            done_run['vol_path'] = vol_path
            done_run['api_key'] = api_key

            # config.parse_options()
            my_ve = VolExp(config)
            ve_calc = my_ve.calculate()
            my_ve.render_text(None, ve_calc, root)


if __name__ == '__main__':
    '''
    call volexp.py with hexdump|cmdplugins and args to get the new window(hexdump|cmdplugins)
    open in a new process.
    '''
    main()

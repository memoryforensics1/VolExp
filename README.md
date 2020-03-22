# VolExp
## Volatility Explorer
 
This program allows the user to access a Memory Dump. It can also function as a plugin to the Volatility Framework (<https://github.com/volatilityfoundation/volatility>).
This program functions similarly to Process Explorer/Hacker, but additionally it allows the user access to a Memory Dump (or access the real-time memory on the computer using Memtriag).
This program can run from Windows and Linux machines, but can only use Windows memory images.

### Quick Start
1. Download the volexp.py file (download the memtriage.py file as well and replace it with your memtriage.py file if you want to use memtriage <https://github.com/gleeda/memtriage>).

2. Run as a standalone program or as a plugin to Volatility:
- As a standalone program:
```shell
 python2 volexp
 ```
 - As a Volatility plugin:
```shell
 python2 vol.py -f <memory file path> --profile=<memory profile> volexp
 ```


### Some Features:
```shell
python2 memtriage.py --plugins=volexp
```
- Some of the information display will not update in real time (except Processes info(update slowly),  real time functions like struct analyzer, PE properties, run real time plugin, etc.).
![example memtriage, the colors used to identify special processes (serviceses, protected)](https://github.com/memoryforensics1/info/blob/master/Win10Example.GIF)



- The program also allows to view Loaded dll's, open handles and network connections of each process (Access to a dll's properties is 
also optional).

![Lower Pane](https://github.com/memoryforensics1/info/blob/master/Win10Handles.png)



- To present more information of a process, Double-Click (or Left-Click and select Properties) to bring up an information window.

![Process properties](https://github.com/memoryforensics1/info/blob/master/ProcessProperties.PNG)



- The program allows the user to view the files in the Memory Dump as well as their information. Additionally it allows the user to extract those files (HexDump/strings view is also optional).

![File Explorer](https://github.com/memoryforensics1/info/blob/master/FileExplorer.PNG)



- The program supports viewing of the Windows Objects and files's matadata (MFT). 

![Other Explorers (Winobj and MFT explorer)](https://github.com/memoryforensics1/info/blob/master/explorers.GIF)



- Additionally, the program supports struct analysis. (writing on the memory's struct, running Volatility functions on a struct is available).
 Example of getting the token sids from the _EPROCESS struct:

![Struct Analyzer](https://github.com/memoryforensics1/info/blob/master/StructAnalyzer.png)



- The Program is also capable of automatically marking suspicious processes found by the plugin.
Example of a running threadmap plugin:

![Cmd Plugin run threadmap](https://github.com/memoryforensics1/info/blob/master/threadmapExample.GIF)


- Manually marking a certain process and adding a sidenote on it. 

- User's actions can be saved on a seperate file for later usage.

### get help :
![volexp help](https://github.com/memoryforensics1/info/blob/master/help.gif)

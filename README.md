>Whoever conceals their syns does not prosper..<br/>

*-Proverbs 28:13*
# The Godspeed Project
2 Python port scanners I created to help speed up certain CTF tasks, but mostly just for fun. Like many other homemade port scanners, the goal was to quickly identify open ports, which could then be taken to nmap for further enumeration.</br>
The functional speed is heavily dependant on network connection, and various target/scanner/host configurations. More on that below.<br/>
As of godspeed v1.1.0, the fastest average is 7.41 seconds for all 65,535 ports.<br/>

godspeed.py - Multi-threaded TCP Connect scanner<br/>
originalSYN.py - Single-threaded SYN scanner<br/>

Neither of them were designed to be subtle, and are obviously not meant for "professional" use.<br/>
## godspeed.py
Description blah blah blah
### Usage
```
$./godspeed.py 192.168.1.50
```
### Notes and Issues
- Some target systems won't respond to requests to closed ports, which leads to godspeed.py relying on the connection timeout, thus absolutely tanking the scan time. This was the #1 cause of increased scan time.
  - This can be mitigated by increasing with thread count with ***-w*** or ***--threads*** and decreasing the timeout with ***-t*** or ***--timeout***. This brought a scan against my particular box from 100 to 20 seconds. (Increasing threads beyond default generally won't increase speed in other situations)

## originalSYN.py
descripity description
### Usage
```
$ sudo ./originalSYN.py 192.168.1.50 9090
```
### Notes and Issues
- Requires sudo/root privileges, due to raw socket usage
- Currently only works on linux, because windows does not allow you to use raw sockets for TCP. 

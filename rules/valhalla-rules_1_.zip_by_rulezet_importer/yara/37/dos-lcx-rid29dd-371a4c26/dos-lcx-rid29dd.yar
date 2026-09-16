rule Dos_lcx_RID29DD : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file lcx.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 01:53:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "c:\\Users\\careful_snow\\" ascii
      $s1 = "Desktop\\Htran\\Release\\Htran.pdb" ascii
      $s3 = "[SERVER]connection to %s:%d error" fullword ascii
      $s4 = "-tran  <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
      $s6 = "=========== Code by lion & bkbll, Welcome to [url]http://www.cnhonker.com[/url] " ascii
      $s7 = "[-] There is a error...Create a new connection." fullword ascii
      $s8 = "[+] Accept a Client on port %d from %s" fullword ascii
      $s11 = "-slave  <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
      $s13 = "[+] Make a Connection to %s:%d...." fullword ascii
      $s16 = "-listen <ConnectPort> <TransmitPort>" fullword ascii
      $s17 = "[+] Waiting another Client on port:%d...." fullword ascii
      $s18 = "[+] Accept a Client on port %d from %s ......" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 2 of them
}
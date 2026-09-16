rule CN_Honker_lcx_lcx_RID2DB4 : CHINA DEMO EXE FILE HKTL T1020 T1090 {
   meta:
      description = "Sample from CN Honker Pentest Toolset - HTRAN - file lcx.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 10:43:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1020, T1090"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%s -<listen|tran|slave> <option> [-log logfile]" fullword ascii
      $s2 = "=========== Code by lion & bkbll" ascii
      $s3 = "Welcome to [url]http://www.cnhonker.com[/url] " ascii
      $s4 = "-tran   <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
      $s5 = "[+] Start Transmit (%s:%d <-> %s:%d) ......" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 30KB and 1 of them
}
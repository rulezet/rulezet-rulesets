rule CN_Honker__wwwscan_wwwscan_wwwscan_gui_RID36A6 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - from files wwwscan.exe, wwwscan.exe, wwwscan_gui.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 17:04:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6bed45629c5e54986f2d27cbfc53464108911026"
      hash2 = "897b66a34c58621190cb88e9b2a2a90bf9b71a53"
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "GET /nothisexistpage.html HTTP/1.1" fullword ascii
      $s2 = "<Usage>:  %s <HostName|Ip> [Options]" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them
}
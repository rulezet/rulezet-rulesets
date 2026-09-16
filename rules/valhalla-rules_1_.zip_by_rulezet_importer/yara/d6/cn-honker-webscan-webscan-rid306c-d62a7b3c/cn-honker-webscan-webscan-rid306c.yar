rule CN_Honker_WebScan_WebScan_RID306C : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file WebScan.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:39:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "wwwscan.exe" fullword wide
      $s2 = "WWWScan Gui" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 700KB and all of them
}
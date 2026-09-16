rule CN_Honker_CoolScan_scan_RID2FDD : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file scan.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:15:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "User-agent:\\s{0,32}(huasai|huasai/1.0|\\*)" fullword ascii
      $s1 = "scan web.exe" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3680KB and all of them
}
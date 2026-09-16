rule CN_Honker_ms10048_x64_RID2DE5 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file ms10048-x64.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 10:51:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[ ] Creating evil window" fullword ascii
      $s2 = "[+] Set to %d exploit half succeeded" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 125KB and all of them
}
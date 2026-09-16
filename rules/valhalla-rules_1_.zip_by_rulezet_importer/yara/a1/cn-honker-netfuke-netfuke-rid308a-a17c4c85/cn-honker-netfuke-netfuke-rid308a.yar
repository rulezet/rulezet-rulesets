rule CN_Honker_NetFuke_NetFuke_RID308A : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file NetFuke.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:44:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Mac Flood: Flooding %dT %d p/s " fullword ascii
      $s2 = "netfuke_%s.txt" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1840KB and all of them
}
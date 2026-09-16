rule CN_Honker_SAMInside_RID2E04 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file SAMInside.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 10:56:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "www.InsidePro.com" fullword wide
      $s1 = "SAMInside.exe" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 650KB and all of them
}
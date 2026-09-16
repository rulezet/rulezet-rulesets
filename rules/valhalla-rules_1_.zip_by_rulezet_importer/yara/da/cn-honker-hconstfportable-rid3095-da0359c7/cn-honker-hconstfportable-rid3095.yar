rule CN_Honker_HconSTFportable_RID3095 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file HconSTFportable.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:46:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "HconSTFportable.exe" fullword wide
      $s2 = "www.Hcon.in" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 354KB and all of them
}
rule CN_Honker_SwordHonkerEdition_RID3209 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file SwordHonkerEdition.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:48:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\bin\\systemini\\MyPort.ini" wide
      $s1 = "PortThread=200 //" fullword wide
      $s2 = " Port Open -> " fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 375KB and all of them
}
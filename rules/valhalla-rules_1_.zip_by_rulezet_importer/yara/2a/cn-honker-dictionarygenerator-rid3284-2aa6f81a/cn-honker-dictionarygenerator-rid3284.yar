rule CN_Honker_DictionaryGenerator_RID3284 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file DictionaryGenerator.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:08:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "`PasswordBuilder" fullword ascii
      $s2 = "cracker" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3650KB and all of them
}
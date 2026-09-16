rule CN_Honker_HASH_32_RID2CAF : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file 32.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 09:59:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "[Undefined OS version]  Major: %d Minor: %d" fullword ascii
      $s8 = "Try To Run As Administrator ..." fullword ascii
      $s9 = "Specific LUID NOT found" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 240KB and all of them
}
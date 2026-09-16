rule CN_Honker_Arp_EMP_v1_0_RID2EC0 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file Arp EMP v1.0.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:27:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Arp EMP v1.0.exe" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and all of them
}
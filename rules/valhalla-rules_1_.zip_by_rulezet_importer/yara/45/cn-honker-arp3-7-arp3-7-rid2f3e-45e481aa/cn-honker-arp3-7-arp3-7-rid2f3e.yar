rule CN_Honker_arp3_7_arp3_7_RID2F3E : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file arp3.7.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:48:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "CnCerT.Net.SKiller.exe" fullword wide
      $s2 = "www.80sec.com" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 4000KB and all of them
}
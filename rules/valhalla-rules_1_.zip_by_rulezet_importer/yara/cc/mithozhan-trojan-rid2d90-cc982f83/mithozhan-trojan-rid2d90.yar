rule Mithozhan_Trojan_RID2D90 : APT DEMO EXE FILE {
   meta:
      description = "Mitozhan Trojan used in APT Terracotta"
      author = "Florian Roth"
      reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
      date = "2015-08-04 10:37:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "adbrowser" fullword wide
      $s2 = "IJKLlGdmaWhram0vn36BgIOChYR3L45xcHNydXQvhmloa2ptbH8voYCDTw==" fullword ascii
      $s3 = "EFGHlGdmaWhrL41sf36BgIOCL6R3dk8=" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them
}
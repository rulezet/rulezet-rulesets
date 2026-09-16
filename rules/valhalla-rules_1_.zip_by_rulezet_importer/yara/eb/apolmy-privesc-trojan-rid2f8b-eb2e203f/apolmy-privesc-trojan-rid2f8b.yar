rule Apolmy_Privesc_Trojan_RID2F8B : APT DEMO EXE FILE T1068 {
   meta:
      description = "Apolmy Privilege Escalation Trojan used in APT Terracotta"
      author = "Florian Roth"
      reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
      date = "2015-08-04 12:01:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE, T1068"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[%d] Failed, %08X" fullword ascii
      $s2 = "[%d] Offset can not fetched." fullword ascii
      $s3 = "PowerShadow2011" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them
}
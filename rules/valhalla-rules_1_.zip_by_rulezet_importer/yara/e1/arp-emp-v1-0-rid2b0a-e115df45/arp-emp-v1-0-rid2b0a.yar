rule Arp_EMP_v1_0_RID2B0A : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file Arp EMP v1.0.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 08:49:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Arp EMP v1.0.exe" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 800KB and all of them
}
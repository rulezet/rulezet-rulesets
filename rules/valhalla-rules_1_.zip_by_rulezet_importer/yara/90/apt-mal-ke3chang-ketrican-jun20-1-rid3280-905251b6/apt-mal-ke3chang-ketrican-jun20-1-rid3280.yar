rule APT_MAL_Ke3chang_Ketrican_Jun20_1_RID3280 : APT DEMO EXE G0004 MAL ketrican {
   meta:
      description = "Detects Ketrican malware"
      author = "Florian Roth"
      reference = "BfV Cyber-Brief Nr. 01/2020"
      date = "2020-06-18 14:07:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "02ea0bc17875ab403c05b50205389065283c59e01de55e68cee4cf340ecea046"
      hash2 = "f3efa600b2fa1c3c85f904a300fec56104d2caaabbb39a50a28f60e0fdb1df39"
      tags = "APT, DEMO, EXE, G0004, MAL, ketrican"
      minimum_yara = "3.5.0"
      
   strings:
      $xc1 = { 00 59 89 85 D4 FB FF FF 8B 85 D4 FB FF FF 89 45 FC 68 E0 58 40 00 8F 45 FC E9 } 
      $op1 = { 6a 53 58 66 89 85 24 ff ff ff 6a 79 58 66 89 85 } 
      $op2 = { 8d 45 bc 50 53 53 6a 1c 8d 85 10 ff ff ff 50 ff } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 1 of ( $x* ) or 2 of them
}
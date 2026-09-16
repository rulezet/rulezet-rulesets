rule APT_MAL_LNX_RedMenshen_BPFDoor_Controller_May22_1_RID3890 : APT DEMO LINUX MAL T1070_003 {
   meta:
      description = "Detects unknown Linux implants (uploads from KR and MO)"
      author = "Florian Roth"
      reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
      date = "2022-05-05 18:26:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "07ecb1f2d9ffbd20a46cd36cd06b022db3cc8e45b1ecab62cd11f9ca7a26ab6d"
      hash2 = "4c5cf8f977fc7c368a8e095700a44be36c8332462c0b1e41bff03238b2bf2a2d"
      hash3 = "599ae527f10ddb4625687748b7d3734ee51673b664f2e5d0346e64f85e185683"
      tags = "APT, DEMO, LINUX, MAL, T1070_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[-] Connect failed." ascii fullword
      $s2 = "export MYSQL_HISTFILE=" ascii fullword
      $s3 = "udpcmd" ascii fullword
      $s4 = "getshell" ascii fullword
      $op1 = { e8 ?? ff ff ff 80 45 ee 01 0f b6 45 ee 3b 45 d4 7c 04 c6 45 ee 00 80 45 ff 01 80 7d ff 00 } 
      $op2 = { 55 48 89 e5 48 83 ec 30 89 7d ec 48 89 75 e0 89 55 dc 83 7d dc 00 75 0? } 
      $op3 = { e8 a? fe ff ff 0f b6 45 f6 48 03 45 e8 0f b6 10 0f b6 45 f7 48 03 45 e8 0f b6 00 8d 04 02 } 
      $op4 = { c6 80 01 01 00 00 00 48 8b 45 c8 0f b6 90 01 01 00 00 48 8b 45 c8 88 90 00 01 00 00 c6 45 ef 00 0f b6 45 ef 88 45 ee } 
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 80KB and 2 of them or 5 of them
}
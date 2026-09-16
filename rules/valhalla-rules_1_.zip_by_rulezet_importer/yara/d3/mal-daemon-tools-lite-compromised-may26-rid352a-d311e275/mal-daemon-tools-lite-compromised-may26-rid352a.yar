rule MAL_DAEMON_Tools_Lite_Compromised_May26_RID352A : DEMO EXE FILE MAL T1020 {
   meta:
      description = "Detects compromised DAEMON Tools Lite versions deployed in a supplychain compromise campaign affected versions include: 12.5.0.2421 up to 12.5.0.2434 The infected binaries drop Quic RAT and various custom data exfiltration payloads."
      author = "Jonathan Peters (cod3nym)"
      reference = "https://securelist.com/tr/daemon-tools-backdoor/119654/"
      date = "2026-05-05 16:01:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL, T1020"
      minimum_yara = "3.5.0"
      
   strings:
      $sa1 = { 31 03 35 55 e4 c4 32 2d a9 e0 b3 81 6d 14 38 4e } 
      $sa2 = "AVB Disc Soft, SIA" ascii
      $sa3 = "DAEMON Tools Lite" ascii wide
      $re = /12\.5\.0\.24(21|22|23|24|25|26|27|28|29|30|31|33|34)/ ascii wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and all of ( $sa* ) and $re
}
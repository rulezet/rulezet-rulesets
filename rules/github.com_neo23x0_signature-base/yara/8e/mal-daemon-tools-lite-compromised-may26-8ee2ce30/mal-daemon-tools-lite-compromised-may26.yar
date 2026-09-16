rule MAL_DAEMON_Tools_Lite_Compromised_May26 {
   meta:
      description = "Detects compromised DAEMON Tools Lite versions deployed in a supplychain compromise campaign affected versions include: 12.5.0.2421 up to 12.5.0.2434 The infected binaries drop Quic RAT and various custom data exfiltration payloads."
      author = "Jonathan Peters (cod3nym)"
      date = "2026-05-05"
      reference = "https://securelist.com/tr/daemon-tools-backdoor/119654/"
      hash = "12edcaafab7703d0819b1395f45c35e3083dd83fb8b128292cb11033453fb6e8"
      hash = "0066ed9b9de2b8e251f7bcf73edcb549218179398cf90124a221958fedce6212"
      hash = "d2a5c9cbb73849cc0667987c33a9bf3822718e1528faef005f1628de3348ffb0"
      score = 80
      id = "68b6838a-6075-576b-af90-77c244d4d7a0"
   strings:
      $sa1 = { 31 03 35 55 e4 c4 32 2d a9 e0 b3 81 6d 14 38 4e }        $sa2 = "AVB Disc Soft, SIA" ascii
      $sa3 = "DAEMON Tools Lite" ascii wide

      $re = /12\.5\.0\.24(21|22|23|24|25|26|27|28|29|30|31|33|34)/ ascii wide
   condition:
      uint16(0) == 0x5a4d
      and all of ($sa*)
      and $re
}
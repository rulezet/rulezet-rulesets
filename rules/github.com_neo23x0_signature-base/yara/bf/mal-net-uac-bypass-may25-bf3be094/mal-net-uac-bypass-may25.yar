rule MAL_NET_UAC_Bypass_May25 {
   meta:
      description = "Detects .NET based tool abusing legitimate Windows utility cmstp.exe to bypass UAC (User-Admin-Controls)"
      author = "Jonathan Peters (cod3nym)"
      date = "2025-05-21"
      reference = "Internal Research"
      hash = "4f12c5dca2099492d0c0cd22edef841cbe8360af9be2d8e9b57c2f83d401c1a7"
      hash = "fcad234dc2ad5e2d8215bcf6caac29aef62666c34564e723fa6d2eee8b6468ed"
      score = 80
   strings:
      $x1 = "CmstpBypass" ascii
      $x2 = { 52 00 45 00 50 00 4C 00 41 00 43 00 45 00 5F 00 43 00 4F 00 4D 00 4D 00 41 00 4E 00 44 00 5F 00 4C 00 49 00 4E 00 45 00 00 13 63 00 6D 00 73 00 74 00 70 00 2E 00 65 00 78 00 65 00 00 33 63 00 6D 00 73 00 74 00 70 00 2E 00 65 00 78 00 65 }
      $x3 = { 52 00 45 00 50 00 4C 00 41 00 43 00 45 00 5F 00 43 00 4F 00 4D 00 4D 00 41 00 4E 00 44 00 5F 00 4C 00 49 00 4E 00 45 00 0D 00 0A 00 74 00 61 00 73 00 6B 00 6B 00 69 00 6C 00 6C 00 20 00 2F 00 49 00 4D 00 20 00 63 00 6D 00 73 00 74 00 70 00 2E 00 65 00 78 00 65 }
   condition:
      uint16(0) == 0x5a4d
      and $x1
      or 1 of ($x2,$x3)
}
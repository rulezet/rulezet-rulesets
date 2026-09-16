rule APT_Lazarus_RAT_Jun18_2 {
   meta:
      description = "Detects Lazarus Group RAT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/DrunkBinary/status/1002587521073721346"
      date = "2018-06-01"
      hash1 = "e6096fb512a6d32a693491f24e67d772f7103805ad407dc37065cebd1962a547"
      id = "4f2e280e-ed76-5fb9-b137-5191bbea2155"
   strings:
      $s1 = "\\KB\\Release\\" ascii
      $s3 = "KB, Version 1.0" fullword wide
      $s4 = "TODO: (c) <Company name>.  All rights reserved." fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and 2 of them
}
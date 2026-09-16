rule CN_Hacktool_MilkT_Scanner {
   meta:
      description = "Detects a chinese Portscanner named MilkT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "12.10.2014"
      id = "aa83c983-25c2-5051-88a1-fbc70d947d6e"
   strings:
      $s0 = "Bf **************" ascii fullword
      $s1 = "forming Time: %d/" ascii
      $s2 = "KERNEL32.DLL" ascii fullword
      $s3 = "CRTDLL.DLL" ascii fullword
      $s4 = "WS2_32.DLL" ascii fullword
      $s5 = "GetProcAddress" ascii fullword
      $s6 = "atoi" ascii fullword
   condition:
      all of them
}
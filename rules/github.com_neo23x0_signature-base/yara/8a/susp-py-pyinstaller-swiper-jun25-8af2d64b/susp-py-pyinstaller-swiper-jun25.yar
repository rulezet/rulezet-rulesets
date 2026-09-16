rule SUSP_PY_PYInstaller_Swiper_Jun25 {
   meta:
      description = "Detects suspicious Python based executable with similarities to a known disk wiper"
      author = "Florian Roth"
      reference = "https://x.com/cyb3rops/status/1935707307805134975"
      date = "2025-06-19"
      score = 65
      hash1 = "4f669ecbe12e95d51f37be76933de4c2626d20bb01729086ce2efc603c4ffdf3"
   strings:
      $a1 = "bzlib1.dll" ascii fullword
      $a2 = "VCRUNTIME140_1.dll" wide fullword
      $a3 = "%s%c%s.exe" ascii fullword

      $sc1 = { 73 77 69 70 65 72 00 00 00 }    condition:
      uint16(0) == 0x5a4d
      and filesize < 40000KB
      and all of them
}
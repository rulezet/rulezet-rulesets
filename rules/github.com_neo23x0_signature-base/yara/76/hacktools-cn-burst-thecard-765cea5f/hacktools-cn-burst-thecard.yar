rule Hacktools_CN_Burst_Thecard {
   meta:
      description = "Disclosed hacktool set - file Thecard.bat"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "17.11.14"
      score = 60
      hash = "50b01ea0bfa5ded855b19b024d39a3d632bacb4c"
      id = "a9946aeb-2042-522f-8d91-f8b96341bb64"
   strings:
      $s0 = "tasklist |find \"Clear.bat\"||start Clear.bat" fullword ascii
      $s1 = "Http://www.coffeewl.com" fullword ascii
      $s2 = "ping -n 2 localhost 1>nul 2>nul" fullword ascii
      $s3 = "for /L %%a in (" ascii
      $s4 = "MODE con: COLS=42 lines=5" fullword ascii
   condition:
      all of them
}
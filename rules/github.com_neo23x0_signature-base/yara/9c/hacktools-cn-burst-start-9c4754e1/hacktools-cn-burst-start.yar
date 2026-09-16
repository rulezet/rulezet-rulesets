rule Hacktools_CN_Burst_Start {
   meta:
      description = "Disclosed hacktool set - file Start.bat - DoS tool"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "2014-11-17"
      modified = "2023-01-27"
      score = 60
      hash = "75d194d53ccc37a68286d246f2a84af6b070e30c"
      id = "1291fbc5-fbb3-5425-bb9a-e45f4d7cf562"
   strings:
      $s0 = "for /f \"eol= tokens=1,2 delims= \" %%i in (ip.txt) do (" ascii
      $s1 = "Blast.bat /r 600" fullword ascii
      $s2 = "Blast.bat /l Blast.bat" fullword ascii
      $s3 = "Blast.bat /c 600" fullword ascii
      $s4 = "start Clear.bat" fullword ascii
      $s5 = "del Result.txt" fullword ascii
      $s6 = "s syn %%i %%j 3306 /save" fullword ascii
      $s7 = "start Thecard.bat" fullword ascii
      $s10 = "setlocal enabledelayedexpansion" fullword ascii
   condition:
      5 of them
}
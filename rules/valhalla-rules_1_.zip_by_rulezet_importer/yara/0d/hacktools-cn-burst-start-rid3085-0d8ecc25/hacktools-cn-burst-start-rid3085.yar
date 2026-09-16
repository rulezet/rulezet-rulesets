rule Hacktools_CN_Burst_Start_RID3085 : CHINA DEMO SCRIPT SUSP {
   meta:
      description = "Disclosed hacktool set - file Start.bat - DoS tool"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-17 12:43:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-20"
      tags = "CHINA, DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
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
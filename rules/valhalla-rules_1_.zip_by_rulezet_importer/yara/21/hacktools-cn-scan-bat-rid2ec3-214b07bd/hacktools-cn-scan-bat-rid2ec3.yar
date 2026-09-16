rule Hacktools_CN_Scan_BAT_RID2EC3 : CHINA DEMO SCRIPT SUSP {
   meta:
      description = "Disclosed hacktool set - file scan.bat"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-17 11:28:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "for /f %%a in (host.txt) do (" ascii
      $s1 = "for /f \"eol=S tokens=1 delims= \" %%i in (s2.txt) do echo %%i>>host.txt" fullword ascii
      $s2 = "del host.txt /q" fullword ascii
      $s3 = "for /f \"eol=- tokens=1 delims= \" %%i in (result.txt) do echo %%i>>s1.txt" fullword ascii
      $s4 = "start Http.exe %%a %http%" fullword ascii
      $s5 = "for /f \"eol=P tokens=1 delims= \" %%i in (s1.txt) do echo %%i>>s2.txt" fullword ascii
   condition: 
      5 of them
}
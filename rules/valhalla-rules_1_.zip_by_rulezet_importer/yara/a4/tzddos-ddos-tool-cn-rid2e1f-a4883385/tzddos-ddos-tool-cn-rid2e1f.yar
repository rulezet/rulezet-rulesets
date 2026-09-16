rule Tzddos_DDoS_Tool_CN_RID2E1F : CHINA DEMO SUSP {
   meta:
      description = "Disclosed hacktool set - file tzddos"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-17 11:01:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "for /f %%a in (host.txt) do (" ascii
      $s1 = "for /f \"eol=S tokens=1 delims= \" %%i in (s2.txt) do echo %%i>>host.txt" fullword ascii
      $s2 = "del host.txt /q" fullword ascii
      $s3 = "for /f \"eol=- tokens=1 delims= \" %%i in (result.txt) do echo %%i>>s1.txt" fullword ascii
      $s4 = "start Http.exe %%a %http%" fullword ascii
      $s5 = "for /f \"eol=P tokens=1 delims= \" %%i in (s1.txt) do echo %%i>>s2.txt" fullword ascii
      $s6 = "del Result.txt s2.txt s1.txt " fullword ascii
   condition: 
      all of them
}
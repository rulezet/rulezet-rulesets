rule CN_Hacktool_MilkT_BAT_RID2EAC : CHINA DEMO SCRIPT SUSP {
   meta:
      description = "Detects a chinese Portscanner named MilkT - shipped BAT"
      author = "Florian Roth"
      reference = "-"
      date = "2014-10-12 11:24:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "for /f \"eol=P tokens=1 delims= \" %%i in (s1.txt) do echo %%i>>s2.txt" ascii
      $s1 = "if not \"%Choice%\"==\"\" set Choice=%Choice:~0,1%" ascii
   condition: 
      all of them
}
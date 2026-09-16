rule CN_Hacktool_MilkT_BAT {
   meta:
      description = "Detects a chinese Portscanner named MilkT - shipped BAT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 70
      date = "12.10.2014"
      id = "d680a5f1-6182-5bc8-99de-c3cba1a61903"
   strings:
      $s0 = "for /f \"eol=P tokens=1 delims= \" %%i in (s1.txt) do echo %%i>>s2.txt" ascii
      $s1 = "if not \"%Choice%\"==\"\" set Choice=%Choice:~0,1%" ascii
   condition:
      all of them
}
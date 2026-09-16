rule sql1433_Start_RID2B99 : APT CHINA DEMO SCRIPT {
   meta:
      description = "Chinese Hacktool Set - file Start.bat"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:13:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, CHINA, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "for /f \"eol=- tokens=1 delims= \" %%i in (result.txt) do echo %%i>>s1.txt" fullword ascii
      $s2 = "start creck.bat" fullword ascii
      $s3 = "del s1.txt" fullword ascii
      $s4 = "del Result.txt" fullword ascii
      $s5 = "del s.TXT" fullword ascii
      $s6 = "mode con cols=48 lines=20" fullword ascii
   condition: 
      filesize < 1KB and 2 of them
}
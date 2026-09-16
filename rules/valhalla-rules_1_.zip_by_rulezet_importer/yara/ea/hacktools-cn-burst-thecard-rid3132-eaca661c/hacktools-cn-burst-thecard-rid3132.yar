rule Hacktools_CN_Burst_Thecard_RID3132 : CHINA DEMO SCRIPT SUSP T1057 {
   meta:
      description = "Disclosed hacktool set - file Thecard.bat"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-17 13:12:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP, T1057"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "tasklist |find \"Clear.bat\"||start Clear.bat" fullword ascii
      $s1 = "Http://www.coffeewl.com" fullword ascii
      $s2 = "ping -n 2 localhost 1>nul 2>nul" fullword ascii
      $s3 = "for /L %%a in (" ascii
      $s4 = "MODE con: COLS=42 lines=5" fullword ascii
   condition: 
      all of them
}
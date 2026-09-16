rule CN_Honker_Pk_Pker_RID2D73 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file Pker.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 10:32:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "/msadc/..%5c..%5c..%5c..%5cwinnt/system32/cmd.exe" fullword wide
      $s2 = "msadc/..\\..\\..\\..\\winnt/system32/cmd.exe" fullword wide
      $s3 = "--Made by VerKey&Only_Guest&Bincker" fullword wide
      $s4 = ";APPLET;EMBED;FRAMESET;HEAD;NOFRAMES;NOSCRIPT;OBJECT;SCRIPT;STYLE;" fullword wide
      $s5 = " --Welcome to Www.Pker.In Made by V.K" fullword wide
      $s6 = "Report.dat" fullword wide
      $s7 = ".\\Report.dat" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 500KB and 5 of them
}
rule FourElementSword_Keyainst_EXE_RID326E : DEMO EXE FILE MAL {
   meta:
      description = "Detects FourElementSword Malware"
      author = "Florian Roth"
      reference = "not set"
      date = "2016-03-26 14:04:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "C:\\ProgramData\\Keyainst.exe" fullword ascii
      $s1 = "ShellExecuteA" fullword ascii
      $s2 = "GetStartupInfoA" fullword ascii
      $s3 = "SHELL32.dll" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 48KB and $x1 ) or ( all of them )
}
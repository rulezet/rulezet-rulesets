rule ROKRAT_Nov17_1_RID2B6E : DEMO EXE FILE MAL rokrat {
   meta:
      description = "Detects ROKRAT malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-11-28 09:06:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL, rokrat"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\T+M\\Result\\DocPrint.pdb" ascii
      $s2 = "d:\\HighSchool\\version 13\\2ndBD" ascii
      $s3 = "e:\\Happy\\Work\\Source\\version" ascii
      $x1 = "\\appdata\\local\\svchost.exe" ascii
      $x2 = "c:\\temp\\esoftscrap.jpg" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 15000KB and 1 of them )
}
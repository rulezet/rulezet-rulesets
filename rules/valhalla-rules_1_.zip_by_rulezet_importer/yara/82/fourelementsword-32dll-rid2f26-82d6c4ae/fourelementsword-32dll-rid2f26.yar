rule FourElementSword_32DLL_RID2F26 : DEMO EXE FILE MAL {
   meta:
      description = "Detects FourElementSword Malware"
      author = "Florian Roth"
      reference = "not set"
      date = "2016-03-26 11:44:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "%temp%\\tmp092.tmp" fullword ascii
      $s2 = "%SystemRoot%\\System32\\" ascii
      $s1 = "\\System32\\ctfmon.exe" ascii
      $s3 = "32.dll" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 660KB and $x1 ) or ( all of them )
}
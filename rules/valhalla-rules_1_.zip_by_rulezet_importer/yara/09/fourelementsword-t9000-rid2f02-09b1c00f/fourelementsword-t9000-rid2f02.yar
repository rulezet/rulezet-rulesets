rule FourElementSword_T9000_RID2F02 : DEMO EXE FILE MAL {
   meta:
      description = "Detects FourElementSword Malware"
      author = "Florian Roth"
      reference = "not set"
      date = "2016-03-26 11:38:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "D:\\WORK\\T9000\\" ascii
      $x2 = "%s\\temp\\HHHH.dat" fullword wide
      $s1 = "Elevate.dll" fullword wide
      $s2 = "ResN32.dll" fullword wide
      $s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword wide
      $s4 = "igfxtray.exe" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 500KB and 1 of ( $x* ) ) or ( all of them )
}
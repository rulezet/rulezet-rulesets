rule FourElementSword_ElevateDLL_2_RID3218 : DEMO EXE FILE MAL T1082 {
   meta:
      description = "Detects FourElementSword Malware"
      author = "Florian Roth"
      reference = "not set"
      date = "2016-03-26 13:50:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL, T1082"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Elevate.dll" fullword ascii
      $s2 = "GetSomeF" fullword ascii
      $s3 = "GetNativeSystemInfo" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 25KB and $s1 ) or ( all of them )
}
rule FourElementSword_ResN32DLL_RID309E : DEMO MAL {
   meta:
      description = "Detects FourElementSword Malware"
      author = "Florian Roth"
      reference = "not set"
      date = "2016-03-26 12:47:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\Release\\BypassUAC.pdb" ascii
      $s2 = "\\ResN32.dll" wide
      $s3 = "Eupdate" fullword wide
   condition: 
      all of them
}
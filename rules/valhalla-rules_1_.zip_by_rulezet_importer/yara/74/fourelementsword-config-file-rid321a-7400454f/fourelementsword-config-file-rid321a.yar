rule FourElementSword_Config_File_RID321A : DEMO MAL {
   meta:
      description = "Detects FourElementSword Malware"
      author = "Florian Roth"
      reference = "not set"
      date = "2016-03-26 13:50:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "01,,hccutils.dll,2" fullword ascii
      $s1 = "RegisterDlls=OurDll" fullword ascii
      $s2 = "[OurDll]" fullword ascii
      $s3 = "[DefaultInstall]" fullword ascii
      $s4 = "Signature=\"$Windows NT$\"" fullword ascii
   condition: 
      4 of them
}
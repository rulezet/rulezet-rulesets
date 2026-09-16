rule VBS_dropper_script_Dec17_1_RID30AE : DEMO SCRIPT T1059 {
   meta:
      description = "Detects a supicious VBS script that drops an executable"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-01-01 12:50:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1059"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "TVpTAQEAAAAEAA" 
      $s2 = "TVoAAAAAAAAAAA" 
      $s3 = "TVqAAAEAAAAEAB" 
      $s4 = "TVpQAAIAAAAEAA" 
      $s5 = "TVqQAAMAAAAEAA" 
      $a1 = "= CreateObject(\"Wscript.Shell\")" fullword ascii
   condition: 
      filesize < 600KB and $a1 and 1 of ( $s* )
}
rule HKTL_BypassUac_EXE_RID2D6F : DEMO HKTL SUSP {
   meta:
      description = "Semiautomatically generated YARA rule - file BypassUacDll.aps"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 10:31:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Wole32.dll" wide
      $s3 = "System32\\migwiz" wide
      $s4 = "System32\\migwiz\\CRYPTBASE.dll" wide
      $s5 = "Elevation:Administrator!new:" wide
      $s6 = "BypassUac" wide
   condition: 
      all of them
}
rule HttpBrowser_RAT_Sample2_RID2FCE : APT DEMO EXE FILE G0027 T1574_001 {
   meta:
      description = "Threat Group 3390 APT Sample - HttpBrowser RAT Sample"
      author = "Florian Roth"
      reference = "http://snip.ly/giNB"
      date = "2015-08-06 12:12:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c57c5a2c322af2835ae136b75283eaaeeaa6aa911340470182a9983ae47b8992"
      tags = "APT, DEMO, EXE, FILE, G0027, T1574_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "nKERNEL32.DLL" fullword wide
      $s1 = "WUSER32.DLL" fullword wide
      $s2 = "mscoree.dll" fullword wide
      $s3 = "VPDN_LU.exeUT" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 250KB and all of them
}
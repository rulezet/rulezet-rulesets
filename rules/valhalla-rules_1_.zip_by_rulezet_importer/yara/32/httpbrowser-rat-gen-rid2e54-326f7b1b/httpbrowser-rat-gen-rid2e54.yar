rule HttpBrowser_RAT_Gen_RID2E54 : APT DEMO EXE FILE G0027 GEN T1574_001 {
   meta:
      description = "Threat Group 3390 APT Sample - HttpBrowser RAT Generic"
      author = "Florian Roth"
      reference = "http://snip.ly/giNB"
      date = "2015-08-06 11:09:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0299493ccb175d452866f5e21d023d3e92cd8d28452517d1d19c0f05f2c5ca27"
      hash2 = "065d055a90da59b4bdc88b97e537d6489602cb5dc894c5c16aff94d05c09abc7"
      hash3 = "05c7291db880f94c675eea336ecd66338bd0b1d49ad239cc17f9df08106e6684"
      tags = "APT, DEMO, EXE, FILE, G0027, GEN, T1574_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "%d|%s|%04d/%02d/%02d %02d:%02d:%02d|%ld|%d" fullword wide
      $s1 = "HttpBrowser/1.0" fullword wide
      $s2 = "set cmd : %s" ascii fullword
      $s3 = "\\config.ini" wide fullword
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 45KB and filesize > 20KB and all of them
}
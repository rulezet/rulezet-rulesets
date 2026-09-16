rule Smartniff_RID2ABB : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file Smartniff_RID2ABB.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 08:03:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "smsniff.exe" fullword wide
      $s2 = "support@nirsoft.net0" fullword ascii
      $s3 = "</requestedPrivileges></security></trustInfo></assembly>" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them
}
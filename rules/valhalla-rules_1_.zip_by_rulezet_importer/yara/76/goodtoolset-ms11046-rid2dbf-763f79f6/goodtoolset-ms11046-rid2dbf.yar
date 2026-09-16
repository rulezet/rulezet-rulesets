rule GoodToolset_ms11046_RID2DBF : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file ms11046.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:45:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[*] Token system command" fullword ascii
      $s2 = "[*] command add user 90sec 90sec" fullword ascii
      $s3 = "[*] Add to Administrators success" fullword ascii
      $s4 = "[*] User has been successfully added" fullword ascii
      $s5 = "Program: %s%s%s%s%s%s%s%s%s%s%s" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 840KB and 2 of them
}
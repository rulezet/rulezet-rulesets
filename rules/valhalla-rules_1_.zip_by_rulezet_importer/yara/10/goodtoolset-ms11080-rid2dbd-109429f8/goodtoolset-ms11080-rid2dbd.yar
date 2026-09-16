rule GoodToolset_ms11080_RID2DBD : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file ms11080.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:44:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[*] command add user 90sec 90sec" fullword ascii
      $s2 = "\\ms11080\\Debug\\ms11080.pdb" ascii
      $s3 = "[>] by:Mer4en7y@90sec.org" fullword ascii
      $s4 = "[*] Add to Administrators success" fullword ascii
      $s5 = "[*] User has been successfully added" fullword ascii
      $s6 = "[>] ms11-08 Exploit" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 240KB and 2 of them
}
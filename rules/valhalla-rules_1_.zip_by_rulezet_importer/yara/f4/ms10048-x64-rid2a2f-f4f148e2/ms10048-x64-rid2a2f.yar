rule ms10048_x64_RID2A2F : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file ms10048-x64.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 04:10:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "The target is most likely patched." fullword ascii
      $s2 = "Dojibiron by Ronald Huizer, (c) master#h4cker.us  " fullword ascii
      $s3 = "[ ] Creating evil window" fullword ascii
      $s4 = "[+] Set to %d exploit half succeeded" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 40KB and 1 of them
}
rule mysqlfast_RID2AF5 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file mysqlfast_RID2AF5.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:40:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "Invalid password hash: %s" fullword ascii
      $s3 = "-= MySql Hash Cracker =- " fullword ascii
      $s4 = "Usage: %s hash" fullword ascii
      $s5 = "Hash: %08lx%08lx" fullword ascii
      $s6 = "Found pass: " fullword ascii
      $s7 = "Pass not found" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 900KB and 4 of them
}
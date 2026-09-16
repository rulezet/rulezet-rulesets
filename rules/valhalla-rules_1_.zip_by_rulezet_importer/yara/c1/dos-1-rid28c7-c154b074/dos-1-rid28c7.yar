rule Dos_1_RID28C7 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file 1.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 18:10:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "/churrasco/-->Usage: Churrasco.exe \"command to run\"" fullword ascii
      $s2 = "/churrasco/-->Done, command should have ran as SYSTEM!" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and all of them
}
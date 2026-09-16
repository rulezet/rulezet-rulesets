rule Dos_fp_RID296C : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file fp.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 22:45:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "fpipe -l 53 -s 53 -r 80 192.168.1.101" fullword ascii
      $s2 = "FPipe.exe" fullword wide
      $s3 = "http://www.foundstone.com" fullword ascii
      $s4 = "%s %s port %d. Address is already in use" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 65KB and all of them
}
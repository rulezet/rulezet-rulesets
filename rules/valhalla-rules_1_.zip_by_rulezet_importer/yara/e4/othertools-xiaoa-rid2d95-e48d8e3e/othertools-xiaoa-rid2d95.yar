rule OtherTools_xiaoa_RID2D95 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file xiaoa.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:38:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Usage:system_exp.exe \"cmd\"" fullword ascii
      $s2 = "The shell \"cmd\" success!" fullword ascii
      $s3 = "Not Windows NT family OS." fullword ascii
      $s4 = "Unable to get kernel base address." fullword ascii
      $s5 = "run \"%s\" failed,code: %d" fullword ascii
      $s6 = "Windows Kernel Local Privilege Exploit " fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 2 of them
}
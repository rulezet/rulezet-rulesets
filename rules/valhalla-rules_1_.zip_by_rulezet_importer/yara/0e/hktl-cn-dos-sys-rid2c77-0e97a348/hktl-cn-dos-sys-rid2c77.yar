rule HKTL_CN_Dos_sys_RID2C77 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file sys.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:50:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "'SeDebugPrivilegeOpen " fullword ascii
      $s6 = "Author: Cyg07*2" fullword ascii
      $s12 = "from golds7n[LAG]'J" fullword ascii
      $s14 = "DAMAGE" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 150KB and all of them
}
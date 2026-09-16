rule epathobj_exp64_RID2C74 : CHINA DEMO EXE FILE HKTL T1068 {
   meta:
      description = "Chinese Hacktool Set - file epathobj_exp64_RID2C74.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:49:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1068"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Watchdog thread %d waiting on Mutex" fullword ascii
      $s2 = "Exploit ok run command" fullword ascii
      $s3 = "\\epathobj_exp\\x64\\Release\\epathobj_exp.pdb" ascii
      $s4 = "Alllocated userspace PATHRECORD () %p" fullword ascii
      $s5 = "Mutex object did not timeout, list not patched" fullword ascii
      $s6 = "- inconsistent onexit begin-end variables" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 150KB and 2 of them
}
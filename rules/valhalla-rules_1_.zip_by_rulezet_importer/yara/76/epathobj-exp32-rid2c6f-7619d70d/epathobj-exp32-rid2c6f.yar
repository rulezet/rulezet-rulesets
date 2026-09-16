rule epathobj_exp32_RID2C6F : CHINA DEMO EXE FILE HKTL T1068 {
   meta:
      description = "Chinese Hacktool Set - file epathobj_exp32_RID2C6F.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:49:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1068"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Watchdog thread %d waiting on Mutex" fullword ascii
      $s1 = "Exploit ok run command" fullword ascii
      $s2 = "\\epathobj_exp\\Release\\epathobj_exp.pdb" ascii
      $s3 = "Alllocated userspace PATHRECORD () %p" fullword ascii
      $s4 = "Mutex object did not timeout, list not patched" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 270KB and all of them
}
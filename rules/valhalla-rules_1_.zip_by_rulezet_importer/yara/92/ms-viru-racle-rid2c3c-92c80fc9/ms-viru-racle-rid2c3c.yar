rule Ms_Viru_racle_RID2C3C : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file racle.dll"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:40:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "PsInitialSystemProcess @%p" fullword ascii
      $s1 = "PsLookupProcessByProcessId(%u) Failed" fullword ascii
      $s2 = "PsLookupProcessByProcessId(%u) => %p" fullword ascii
      $s3 = "FirstStage() Loaded, CurrentThread @%p Stack %p - %p" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 210KB and all of them
}
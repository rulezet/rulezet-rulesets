rule CN_Honker_exp_ms11011_RID2E47 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file ms11011.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:07:41"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\i386\\Hello.pdb" ascii
      $s1 = "OS not supported." fullword ascii
      $s2 = ".Rich5" fullword ascii
      $s3 = "Not supported." fullword wide
      $s5 = "cmd.exe" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them
}
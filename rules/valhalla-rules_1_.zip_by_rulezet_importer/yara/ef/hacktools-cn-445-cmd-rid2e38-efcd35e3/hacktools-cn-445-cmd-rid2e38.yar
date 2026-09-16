rule Hacktools_CN_445_cmd_RID2E38 : CHINA DEMO FILE SCRIPT SUSP {
   meta:
      description = "Disclosed hacktool set - file cmd.bat"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-17 11:05:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $bat = "@echo off" fullword ascii
      $s0 = "cs.exe %1" fullword ascii
      $s2 = "nc %1 4444" fullword ascii
   condition: 
      uint32 ( 0 ) == 0x68636540 and $bat at 0 and all of ( $s* )
}
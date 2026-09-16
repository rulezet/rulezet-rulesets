rule RUAG_Bot_Config_File_RID2E58 : APT DEMO FILE {
   meta:
      description = "Detects a specific config file used by malware in RUAG APT case"
      author = "Florian Roth"
      reference = "https://www.ncsc.admin.ch/govcert"
      date = "2016-05-23 11:10:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2026-03-12"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[CONFIG]" ascii
      $s2 = "name = " ascii
      $s3 = "exe = cmd.exe" ascii
   condition: 
      uint32 ( 0 ) == 0x4e4f435b and filesize < 160 and $s1 at 0 and $s2 and $s3
}
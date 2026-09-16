rule RUAG_Cobra_Config_File_RID2F1A : APT DEMO FILE NK {
   meta:
      description = "Detects a config text file used by malware Cobra in RUAG case"
      author = "Florian Roth"
      reference = "https://www.ncsc.admin.ch/govcert"
      date = "2016-05-23 11:42:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2026-03-12"
      tags = "APT, DEMO, FILE, NK"
      minimum_yara = "3.5.0"
      
   strings:
      $h1 = "[NAME]" ascii
      $s1 = "object_id=" ascii
      $s2 = "[TIME]" ascii fullword
      $s3 = "lastconnect" ascii
      $s4 = "[CW_LOCAL]" ascii fullword
      $s5 = "system_pipe" ascii
      $s6 = "user_pipe" ascii
      $s7 = "[TRANSPORT]" ascii
      $s8 = "run_task_system" ascii
      $s9 = "[WORKDATA]" ascii
      $s10 = "address1" ascii
   condition: 
      uint32 ( 0 ) == 0x4d414e5b and filesize < 5KB and $h1 at 0 and 8 of ( $s* )
}
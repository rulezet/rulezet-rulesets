rule RUAG_Exfil_Config_File_RID2F2B : APT DEMO FILE T1020 {
   meta:
      description = "Detects a config text file used in data exfiltration in RUAG case"
      author = "Florian Roth"
      reference = "https://www.ncsc.admin.ch/govcert"
      date = "2016-05-23 11:45:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2026-03-12"
      tags = "APT, DEMO, FILE, T1020"
      minimum_yara = "3.5.0"
      
   strings:
      $h1 = "[TRANSPORT]" ascii
      $s1 = "system_pipe" ascii
      $s2 = "spstatus" ascii
      $s3 = "adaptable" ascii
      $s4 = "post_frag" ascii
      $s5 = "pfsgrowperiod" ascii
   condition: 
      uint32 ( 0 ) == 0x4152545b and filesize < 1KB and $h1 at 0 and all of ( $s* )
}
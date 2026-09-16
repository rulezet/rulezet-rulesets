rule SUSP_LNX_SH_Disk_Wiper_Script_Jun25_RID33BE : DEMO FILE LINUX SCRIPT SUSP {
   meta:
      description = "Detects unknown disk wiper script for Linux systems"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2025-06-19 15:00:51"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f662f69fc7f4240cd8c00661db9484e76b5d02f903590140b4086fefcf9d9331"
      tags = "DEMO, FILE, LINUX, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "THIS SCRIPT IS LIVE AND ARMED!" ascii fullword
      $s2 = "FAIR WARNING!" ascii fullword
      $s3 = "lists devices" ascii fullword
   condition: 
      uint16 ( 0 ) == 0x2123 and filesize < 2KB and all of them
}
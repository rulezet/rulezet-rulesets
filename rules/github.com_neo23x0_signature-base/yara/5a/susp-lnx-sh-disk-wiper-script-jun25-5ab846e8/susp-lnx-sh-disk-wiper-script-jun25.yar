rule SUSP_LNX_SH_Disk_Wiper_Script_Jun25 {
   meta:
      description = "Detects unknown disk wiper script for Linux systems"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2025-06-19"
      score = 65
      hash1 = "f662f69fc7f4240cd8c00661db9484e76b5d02f903590140b4086fefcf9d9331"
   strings:
      $s1 = "THIS SCRIPT IS LIVE AND ARMED!" ascii fullword
      $s2 = "FAIR WARNING!" ascii fullword
      $s3 = "lists devices" ascii fullword
   condition:
      uint16(0) == 0x2123
      and filesize < 2KB
      and all of them
}
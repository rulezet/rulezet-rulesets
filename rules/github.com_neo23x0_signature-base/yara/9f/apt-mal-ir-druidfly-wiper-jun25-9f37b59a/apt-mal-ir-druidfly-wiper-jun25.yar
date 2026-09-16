rule APT_MAL_IR_DruidFly_Wiper_Jun25 {
   meta:
      description = "Detects Wiper used by the Iranian DruidFly group"
      author = "Florian Roth"
      reference = "https://x.com/threatintel/status/1936049254432231444"
      date = "2025-06-21"
      score = 80
      hash1 = "81eb22828306f3197b35fef2035cef2c548f587f8511902852964850023389d7"
   strings:
      $xc1 = { 2E 62 61 63 6B 75 70 00 2E 63 6F 6E 66 69 67 00                  2E 64 62 00 00 00 00 00 2E 73 71 6C 69 74 65 00 }       $xc2 = { 00 5C 5C 2E 5C 25 63 3A 00 25 63 3A 5C 00 00 00
               00 4E 54 46 53 00 00 00 00 5C }  
      $x1 = "%s:%d:%s(): [+] Overwriting \"%s\" \"..." ascii

      $s1 = "C:\\Windows\\System32\\drivers\\beep.sys" ascii fullword
      $s2 = "\\DosDevices\\sectorio" wide fullword
   condition:
      uint16(0) == 0x5a4d
      and filesize < 2000KB
      and ( 
         1 of ($x*)
         or 2 of them
      )
      or 3 of them
}
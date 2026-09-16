rule SUSP_LNK_File_AppData_Roaming {
   meta:
      description = "Detects a suspicious link file that references to AppData Roaming"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2018/05/deep-dive-into-rig-exploit-kit-delivering-grobios-trojan.html"
      date = "2018-05-16"
      score = 50
      id = "d905e58f-ae2e-5dc2-b206-d0435b023df0"
   strings:
      $s2 = "AppData" fullword wide
      $s3 = "Roaming" fullword wide
      
      $s4 = { 00 2E 00 65 00 78 00 65 00 2E 00 43 00 3A 00 5C
              00 55 00 73 00 65 00 72 00 73 00 5C }
   condition:
      uint16(0) == 0x004c and uint32(4) == 0x00021401 and (
         filesize < 1KB and
         all of them
      )
}
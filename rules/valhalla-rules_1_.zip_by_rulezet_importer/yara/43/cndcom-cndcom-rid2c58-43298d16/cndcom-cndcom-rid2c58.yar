rule cndcom_cndcom_RID2C58 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file cndcom.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:45:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "- Rewritten by HDM last <hdm [at] metasploit.com>" fullword ascii
      $s2 = "- Usage: %s <Target ID> <Target IP>" fullword ascii
      $s3 = "- Remote DCOM RPC Buffer Overflow Exploit" fullword ascii
      $s4 = "- Warning:This Code is more like a dos tool!(Modify by pingker)" fullword ascii
      $s5 = "Windows NT SP6 (Chinese)" fullword ascii
      $s6 = "- Original code by FlashSky and Benjurry" fullword ascii
      $s7 = "\\C$\\123456111111111111111.doc" wide
      $s8 = "shell3all.c" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 2 of them
}
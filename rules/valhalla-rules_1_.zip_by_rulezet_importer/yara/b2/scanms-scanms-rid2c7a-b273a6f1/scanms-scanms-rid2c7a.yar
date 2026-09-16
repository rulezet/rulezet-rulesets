rule scanms_scanms_RID2C7A : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file scanms.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:50:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "--- ScanMs Tool --- (c) 2003 Internet Security Systems ---" fullword ascii
      $s2 = "Scans for systems vulnerable to MS03-026 vuln" fullword ascii
      $s3 = "More accurate for WinXP/Win2k, less accurate for WinNT" fullword ascii
      $s4 = "added %d.%d.%d.%d-%d.%d.%d.%d" fullword ascii
      $s5 = "Internet Explorer 1.0" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 3 of them
}
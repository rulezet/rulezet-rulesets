rule HKTL_CN_update_PcMain_RID2EAD : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file PcMain.dll"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 11:24:41"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.2; .NET CLR 1.1.4322" ascii
      $s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" fullword ascii
      $s2 = "SOFTWARE\\Classes\\HTTP\\shell\\open\\command" fullword ascii
      $s3 = "\\svchost.exe -k " ascii
      $s4 = "SYSTEM\\ControlSet001\\Services\\%s" fullword ascii
      $s9 = "Global\\%s-key-event" fullword ascii
      $s10 = "%d%d.exe" fullword ascii
      $s14 = "%d.exe" fullword ascii
      $s15 = "Global\\%s-key-metux" fullword ascii
      $s18 = "GET / HTTP/1.1" fullword ascii
      $s19 = "\\Services\\" ascii
      $s20 = "qy001id=%d;qy001guid=%s" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 500KB and 4 of them
}
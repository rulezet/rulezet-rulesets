rule CN_Honker_WebScan_wwwscan_RID30D3 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file wwwscan.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:56:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%s www.target.com -p 8080 -m 10 -t 16" fullword ascii
      $s2 = "GET /nothisexistpage.html HTTP/1.1" fullword ascii
      $s3 = "<Usage>:  %s <HostName|Ip> [Options]" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 60KB and all of them
}
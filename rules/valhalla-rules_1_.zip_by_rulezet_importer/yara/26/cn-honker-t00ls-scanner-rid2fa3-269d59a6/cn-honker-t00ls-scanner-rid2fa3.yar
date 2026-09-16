rule CN_Honker_T00ls_scanner_RID2FA3 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file T00ls_scanner.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:05:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "http://cn.bing.com/search?first=1&count=50&q=ip:" fullword wide
      $s17 = "Team:www.t00ls.net" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 330KB and all of them
}
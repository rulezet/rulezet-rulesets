rule CN_Honker_shell_brute_tool_RID317D : CHINA DEMO EXE FILE HKTL SCRIPT {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file shell_brute_tool.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:24:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "http://24hack.com/xyadmin.asp" fullword ascii
      $s1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and all of them
}
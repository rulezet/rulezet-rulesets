rule CN_Honker_wwwscan_gui_RID2F75 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file wwwscan_gui.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:58:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%s www.target.com -p 8080 -m 10 -t 16" fullword ascii
      $s2 = "/eye2007Admin_login.aspx" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 280KB and all of them
}
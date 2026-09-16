rule CN_Honker_WebCruiserWVS_RID2FC2 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file WebCruiserWVS.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:10:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "id:uid:user:username:password:access:account:accounts:admin_id:admin_name:admin_" ascii
      $s1 = "Created By WebCruiser - Web Vulnerability Scanner http://sec4app.com" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 700KB and all of them
}
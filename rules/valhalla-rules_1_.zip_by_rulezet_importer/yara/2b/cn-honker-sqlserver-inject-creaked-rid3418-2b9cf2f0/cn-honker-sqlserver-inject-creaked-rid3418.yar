rule CN_Honker_SQLServer_inject_Creaked_RID3418 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file SQLServer_inject_Creaked.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:15:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "http://localhost/index.asp?id=2" fullword ascii
      $s2 = "Email:zhaoxypass@yahoo.com.cn<br>" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 8110KB and all of them
}
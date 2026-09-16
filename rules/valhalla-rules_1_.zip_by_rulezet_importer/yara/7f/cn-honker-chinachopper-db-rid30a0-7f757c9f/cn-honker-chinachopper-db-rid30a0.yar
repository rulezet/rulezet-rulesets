rule CN_Honker_ChinaChopper_db_RID30A0 : CHINA DEMO SCRIPT SUSP {
   meta:
      description = "Script from disclosed CN Honker Pentest Toolset - file db.mdb"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:47:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "http://www.maicaidao.com/server.phpcaidao" fullword wide
      $s2 = "<O>act=login</O>" fullword wide
      $s3 = "<H>localhost</H>" fullword wide
   condition: 
      filesize < 340KB and 2 of them
}
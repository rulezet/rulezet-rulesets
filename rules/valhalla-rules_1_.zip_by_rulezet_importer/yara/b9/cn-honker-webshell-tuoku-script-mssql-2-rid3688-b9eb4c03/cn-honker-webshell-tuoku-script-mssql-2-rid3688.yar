rule CN_Honker_Webshell_Tuoku_script_mssql_2_RID3688 : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file mssql.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 16:59:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "sqlpass=request(\"sqlpass\")" fullword ascii
      $s2 = "set file=fso.createtextfile(server.mappath(request(\"filename\")),8,true)" fullword ascii
      $s3 = "<blockquote> ServerIP:&nbsp;&nbsp;&nbsp;" fullword ascii
   condition: 
      filesize < 3KB and all of them
}
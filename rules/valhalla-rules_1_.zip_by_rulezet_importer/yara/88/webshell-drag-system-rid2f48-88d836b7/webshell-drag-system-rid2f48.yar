rule Webshell_drag_system_RID2F48 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file system.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:50:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s9 = "String sql = \"SELECT * FROM DBA_TABLES WHERE TABLE_NAME not like '%$%' and num_" 
   condition: 
      all of them
}
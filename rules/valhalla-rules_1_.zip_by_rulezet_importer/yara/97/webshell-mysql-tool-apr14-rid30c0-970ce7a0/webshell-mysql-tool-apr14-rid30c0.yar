rule WebShell_mysql_tool_Apr14_RID30C0 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file mysql_tool.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:53:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-01-29"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s12 = "$dump .= \"-- Dumping data for table '$table'\\n\";" fullword
      $s20 = "$dump .= \"CREATE TABLE $table (\\n\";" fullword
   condition: 
      2 of them
}
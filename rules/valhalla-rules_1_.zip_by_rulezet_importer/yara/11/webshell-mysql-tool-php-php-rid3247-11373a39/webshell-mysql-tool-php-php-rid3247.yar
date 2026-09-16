rule Webshell_mysql_tool_php_php_RID3247 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file mysql_tool.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:58:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$error_text = '<strong>Failed selecting database \"'.$this->db['" 
      $s1 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERV" 
      $s4 = "<div align=\"center\">The backup process has now started<br " 
   condition: 
      1 of them
}
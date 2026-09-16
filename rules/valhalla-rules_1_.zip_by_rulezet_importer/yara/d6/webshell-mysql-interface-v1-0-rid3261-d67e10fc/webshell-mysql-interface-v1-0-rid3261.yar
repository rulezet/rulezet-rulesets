rule Webshell_Mysql_interface_v1_0_RID3261 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Mysql interface v1.0.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:02:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "echo \"<td><a href='$PHP_SELF?action=dropDB&dbname=$dbname' onClick=\\\"return" 
   condition: 
      all of them
}
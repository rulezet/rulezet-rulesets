rule Webshell_mysqlwebsh_RID2EF5 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file mysqlwebsh.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:36:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = " <TR><TD bgcolor=\"<? echo (!$CONNECT && $action == \"chparam\")?\"#660000\":\"#" 
   condition: 
      all of them
}
rule Webshell_NetworkFileManagerPHP_A_RID3353 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file NetworkFileManagerPHP.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:43:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s9 = "  echo \"<br><center>All the data in these tables:<br> \".$tblsv.\" were putted " 
   condition: 
      all of them
}
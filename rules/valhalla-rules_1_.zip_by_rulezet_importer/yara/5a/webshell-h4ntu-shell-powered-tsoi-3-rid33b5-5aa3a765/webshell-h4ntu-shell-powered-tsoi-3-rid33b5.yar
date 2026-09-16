rule WEBSHELL_H4ntu_Shell_Powered_Tsoi_3_RID33B5 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file h4ntu shell powered by tsoi.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:59:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-03-21"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>Server Adress:</b" 
      $s3 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>User Info:</b> ui" 
      $s4 = "    <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><?= $info ?>: <?= " 
   condition: 
      2 of them
}
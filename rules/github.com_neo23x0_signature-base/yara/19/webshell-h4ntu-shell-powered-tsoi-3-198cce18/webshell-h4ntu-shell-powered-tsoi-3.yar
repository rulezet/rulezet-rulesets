rule WEBSHELL_H4ntu_Shell_Powered_Tsoi_3 {
   meta:
      description = "Web Shell - file h4ntu shell powered by tsoi.php"
      author = "Florian Roth"
      date = "2014-01-28"
      modified = "2025-03-21"
      score = 70
      old_rule_name = "Webshell_h4ntu_shell_powered_by_tsoi_"
      hash = "06ed0b2398f8096f1bebf092d0526137"
   strings:
      $s0 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>Server Adress:</b"
      $s3 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>User Info:</b> ui"
      $s4 = "    <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><?= $info ?>: <?= "
   condition:
      2 of them
}
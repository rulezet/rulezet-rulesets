rule Webshell_rst_sql_php_php_RID30FC : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file rst_sql.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:03:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "C:\\tmp\\dump_" 
      $s1 = "RST MySQL" 
      $s2 = "http://rst.void.ru" 
      $s3 = "$st_form_bg='R0lGODlhCQAJAIAAAOfo6u7w8yH5BAAAAAAALAAAAAAJAAkAAAIPjAOnuJfNHJh0qtfw0lcVADs=';" 
   condition: 
      2 of them
}
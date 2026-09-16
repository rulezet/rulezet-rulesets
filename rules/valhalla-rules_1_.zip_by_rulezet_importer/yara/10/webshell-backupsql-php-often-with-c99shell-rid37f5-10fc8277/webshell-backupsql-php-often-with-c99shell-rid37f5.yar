rule Webshell_backupsql_php_often_with_c99shell_RID37F5 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file backupsql.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 18:00:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "//$message.= \"--{$mime_boundary}\\n\" .\"Content-Type: {$fileatt_type};\\n\" ." 
      $s4 = "$ftpconnect = \"ncftpput -u $ftp_user_name -p $ftp_user_pass -d debsender_ftplog" 
   condition: 
      all of them
}
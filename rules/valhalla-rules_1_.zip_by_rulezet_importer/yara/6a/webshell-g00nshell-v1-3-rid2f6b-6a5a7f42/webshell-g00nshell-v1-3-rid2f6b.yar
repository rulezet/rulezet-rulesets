rule WebShell_g00nshell_v1_3_RID2F6B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file g00nshell-v1.3.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:56:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s10 = "#To execute commands, simply include ?cmd=___ in the url. #" fullword
      $s15 = "$query = \"SHOW COLUMNS FROM \" . $_GET['table'];" fullword
      $s16 = "$uakey = \"724ea055b975621b9d679f7077257bd9\"; // MD5 encoded user-agent" fullword
      $s17 = "echo(\"<form method='GET' name='shell'>\");" fullword
      $s18 = "echo(\"<form method='post' action='?act=sql'>\");" fullword
   condition: 
      2 of them
}
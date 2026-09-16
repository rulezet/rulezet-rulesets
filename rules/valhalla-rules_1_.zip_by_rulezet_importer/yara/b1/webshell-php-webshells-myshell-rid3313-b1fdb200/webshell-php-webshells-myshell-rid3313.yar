rule WebShell_php_webshells_MyShell_RID3313 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file MyShell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 14:32:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "<title>MyShell error - Access Denied</title>" fullword
      $s4 = "$adminEmail = \"youremail@yourserver.com\";" fullword
      $s5 = "//A workdir has been asked for - we chdir to that dir." fullword
      $s6 = "system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/o" 
      $s13 = "#$autoErrorTrap Enable automatic error traping if command returns error." fullword
      $s14 = "/* No work_dir - we chdir to $DOCUMENT_ROOT */" fullword
      $s19 = "#every command you excecute." fullword
      $s20 = "<form name=\"shell\" method=\"post\">" fullword
   condition: 
      3 of them
}
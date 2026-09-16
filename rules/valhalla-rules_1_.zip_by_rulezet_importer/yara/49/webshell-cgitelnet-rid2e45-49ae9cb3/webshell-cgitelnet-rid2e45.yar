rule WebShell_cgitelnet_RID2E45 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file cgitelnet.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:07:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s9 = "# Author Homepage: http://www.rohitab.com/" fullword
      $s10 = "elsif($Action eq \"command\") # user wants to run a command" fullword
      $s18 = "# in a command line on Windows NT." fullword
      $s20 = "print \"Transfered $TargetFileSize Bytes.<br>\";" fullword
   condition: 
      2 of them
}
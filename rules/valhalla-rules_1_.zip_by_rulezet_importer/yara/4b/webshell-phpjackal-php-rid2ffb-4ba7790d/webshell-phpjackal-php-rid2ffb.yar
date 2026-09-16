rule Webshell_phpjackal_php_RID2FFB : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file phpjackal.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:20:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "$dl=$_REQUEST['downloaD'];" 
      $s4 = "else shelL(\"perl.exe $name $port\");" 
   condition: 
      1 of them
}
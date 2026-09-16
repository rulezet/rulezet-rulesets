rule Webshell_itsec_itsecteam_shell_jHn_RID34D2 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files itsec.php, itsecteam_shell.php, jHn.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:46:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "bd6d3b2763c705a01cc2b3f105a25fa4"
      hash2 = "40c6ecf77253e805ace85f119fe1cebb"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "echo $head.\"<font face='Tahoma' size='2'>Operating System : \".php_uname().\"<b" 
      $s5 = "echo \"<center><form name=client method='POST' action='$_SERVER[PHP_SELF]?do=db'" 
   condition: 
      all of them
}
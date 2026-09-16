rule Webshell_sh_php_php_RID2ECF : DEMO SCRIPT T1087_001 T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file sh.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:30:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1087_001, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$ar_file=array('/etc/passwd','/etc/shadow','/etc/master.passwd','/etc/fstab','/e" 
      $s2 = "Show <input type=text size=5 value=\".((isset($_POST['br_st']))?$_POST['br_st']:" 
   condition: 
      1 of them
}
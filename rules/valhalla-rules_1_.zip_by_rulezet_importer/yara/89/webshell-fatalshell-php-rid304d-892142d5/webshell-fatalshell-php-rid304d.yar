rule Webshell_Fatalshell_php_RID304D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files antichat.php.php.txt, Fatalshell.php.php.txt, a_gedit.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:34:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b15583f4eaad10a25ef53ab451a4a26d"
      hash2 = "ab9c6b24ca15f4a1b7086cad78ff0f78"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "if(@$_POST['save'])writef($file,$_POST['data']);" fullword
      $s1 = "if($action==\"phpeval\"){" fullword
      $s2 = "$uploadfile = $dirupload.\"/\".$_POST['filename'];" fullword
      $s3 = "$dir=getcwd().\"/\";" fullword
   condition: 
      2 of them
}
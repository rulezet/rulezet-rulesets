rule Webshell_ru24_post_sh_php_php_RID32A0 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file ru24_post_sh.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:13:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<title>Ru24PostWebShell - \".$_POST['cmd'].\"</title>" fullword
      $s3 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a" 
      $s4 = "Writed by DreAmeRz" fullword
   condition: 
      1 of them
}
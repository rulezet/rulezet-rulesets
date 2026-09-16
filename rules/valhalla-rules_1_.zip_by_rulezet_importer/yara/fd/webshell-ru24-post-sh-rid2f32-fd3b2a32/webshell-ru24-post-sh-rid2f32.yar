rule WebShell_ru24_post_sh_RID2F32 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file ru24_post_sh.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:46:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "http://www.ru24-team.net" fullword
      $s4 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a" 
      $s6 = "Ru24PostWebShell" 
      $s7 = "Writed by DreAmeRz" fullword
      $s9 = "$function=passthru; // system, exec, cmd" fullword
   condition: 
      1 of them
}
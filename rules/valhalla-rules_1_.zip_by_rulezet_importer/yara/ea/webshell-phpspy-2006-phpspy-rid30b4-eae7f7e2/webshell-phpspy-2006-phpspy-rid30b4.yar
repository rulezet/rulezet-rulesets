rule Webshell_phpspy_2006_PHPSPY_RID30B4 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files phpspy_2005_full.php, phpspy_2005_lite.php, phpspy_2006.php, PHPSPY.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:51:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "42f211cec8032eb0881e87ebdb3d7224"
      hash2 = "40a1f840111996ff7200d18968e42cfe"
      hash3 = "0712e3dc262b4e1f98ed25760b206836"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "http://www.4ngel.net" fullword
      $s5 = "</a> | <a href=\"?action=phpenv\">PHP" fullword
      $s8 = "echo $msg=@fwrite($fp,$_POST['filecontent']) ? \"" fullword
      $s9 = "Codz by Angel" fullword
   condition: 
      2 of them
}
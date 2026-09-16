rule saphpshell_RID2B45 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file saphpshell_RID2B45.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 08:59:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<td><input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['command']?>" 
   condition: 
      all of them
}
rule Webshell_shankar_php_php_RID30DC : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file shankar.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:57:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-02-17"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $Author = "ShAnKaR" 
      $s0 = "<input type=checkbox name='dd' \".(isset($_POST['dd'])?'checked':'').\">DB<input" 
      $s3 = "Show<input type=text size=5 value=\".((isset($_POST['br_st']) && isset($_POST['b" 
   condition: 
      1 of ( $s* ) and $Author
}
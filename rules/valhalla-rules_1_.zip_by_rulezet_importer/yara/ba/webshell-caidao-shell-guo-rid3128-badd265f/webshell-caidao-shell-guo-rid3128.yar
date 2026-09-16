rule Webshell_caidao_shell_guo_RID3128 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file guo.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:10:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?php ($www= $_POST['ice'])!" 
      $s1 = "@preg_replace('/ad/e','@'.str_rot13('riny').'($ww" 
   condition: 
      1 of them
}
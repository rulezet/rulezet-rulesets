rule WebShell_STNC_WebShell_v0_8_RID30CF : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file STNC WebShell v0.8.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:55:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "if(isset($_POST[\"action\"])) $action = $_POST[\"action\"];" fullword
      $s8 = "elseif(fe(\"system\")){ob_start();system($s);$r=ob_get_contents();ob_end_clean()" 
      $s13 = "{ $pwd = $_POST[\"pwd\"]; $type = filetype($pwd); if($type === \"dir\")chdir($pw" 
   condition: 
      2 of them
}
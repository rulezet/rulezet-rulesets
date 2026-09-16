rule Webshell_zacosmall_RID2E6C : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file zacosmall.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:13:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "if($cmd!==''){ echo('<strong>'.htmlspecialchars($cmd).\"</strong><hr>" 
   condition: 
      all of them
}
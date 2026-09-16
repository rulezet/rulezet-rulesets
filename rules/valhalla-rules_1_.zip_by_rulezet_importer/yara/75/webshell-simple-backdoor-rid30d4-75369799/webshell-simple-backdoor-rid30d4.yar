rule Webshell_simple_backdoor_RID30D4 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file simple-backdoor.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:56:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$cmd = ($_REQUEST['cmd']);" fullword
      $s1 = "if(isset($_REQUEST['cmd'])){" fullword
      $s4 = "system($cmd);" fullword
   condition: 
      2 of them
}
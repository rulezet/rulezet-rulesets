rule Webshell_php_cmd_RID2D81 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file cmd.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:34:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "if($_GET['cmd']) {" fullword
      $s1 = "// cmd.php = Command Execution" fullword
      $s7 = "  system($_GET['cmd']);" fullword
   condition: 
      all of them
}
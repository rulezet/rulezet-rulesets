rule Webshell_phpkit_1_0_odd_RID2FEB : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file odd.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:17:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "include('php://input');" fullword
      $s1 = "// No eval() calls, no system() calls, nothing normally seen as malicious." fullword
      $s2 = "ini_set('allow_url_include, 1'); // Allow url inclusion in this script" fullword
   condition: 
      all of them
}
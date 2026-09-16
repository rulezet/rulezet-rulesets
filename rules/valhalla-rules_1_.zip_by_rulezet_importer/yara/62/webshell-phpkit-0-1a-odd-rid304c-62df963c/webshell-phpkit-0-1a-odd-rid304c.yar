rule Webshell_phpkit_0_1a_odd_RID304C : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file odd.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:33:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "include('php://input');" fullword
      $s3 = "ini_set('allow_url_include, 1'); // Allow url inclusion in this script" fullword
      $s4 = "// uses include('php://input') to execute arbritary code" fullword
      $s5 = "// php://input based backdoor" fullword
   condition: 
      2 of them
}
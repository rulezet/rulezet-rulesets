rule Webshell_ngh_php_php_RID2F31 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file ngh.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:46:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Cr4sh_aka_RKL" 
      $s1 = "NGH edition" 
      $s2 = "/* connectback-backdoor on perl" 
      $s3 = "<form action=<?=$script?>?act=bindshell method=POST>" 
      $s4 = "$logo = \"R0lGODlhMAAwAOYAAAAAAP////r" 
   condition: 
      1 of them
}
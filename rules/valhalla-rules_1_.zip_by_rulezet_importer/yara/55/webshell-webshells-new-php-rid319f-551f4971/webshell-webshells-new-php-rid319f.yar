rule Webshell_webshells_new_pHp_RID319F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file pHp.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:30:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "if(is_readable($path)) antivirus($path.'/',$exs,$matches);" fullword
      $s1 = "'/(eval|assert|include|require|include\\_once|require\\_once|array\\_map|arr" 
      $s13 = "'/(exec|shell\\_exec|system|passthru)+\\s*\\(\\s*\\$\\_(\\w+)\\[(.*)\\]\\s*" 
      $s14 = "'/(include|require|include\\_once|require\\_once)+\\s*\\(\\s*[\\'|\\\"](\\w+" 
      $s19 = "'/\\$\\_(\\w+)(.*)(eval|assert|include|require|include\\_once|require\\_once" 
   condition: 
      1 of them
}
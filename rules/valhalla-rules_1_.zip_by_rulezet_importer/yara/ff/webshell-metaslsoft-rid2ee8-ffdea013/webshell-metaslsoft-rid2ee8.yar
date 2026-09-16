rule Webshell_metaslsoft_RID2EE8 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file metaslsoft.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:34:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "$buff .= \"<tr><td><a href=\\\"?d=\".$pwd.\"\\\">[ $folder ]</a></td><td>LINK</t" 
   condition: 
      all of them
}
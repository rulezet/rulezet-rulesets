rule Webshell_php_list_RID2E09 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file list.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:57:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "// list.php = Directory & File Listing" fullword
      $s2 = "    echo \"( ) <a href=?file=\" . $fichero . \"/\" . $filename . \">\" . $filena" 
      $s9 = "// by: The Dark Raver" fullword
   condition: 
      1 of them
}
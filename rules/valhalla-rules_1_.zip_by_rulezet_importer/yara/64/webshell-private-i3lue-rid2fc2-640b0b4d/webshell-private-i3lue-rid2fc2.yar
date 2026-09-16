rule Webshell_Private_i3lue_RID2FC2 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Private-i3lue.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:10:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s8 = "case 15: $image .= \"\\21\\0\\" 
   condition: 
      all of them
}
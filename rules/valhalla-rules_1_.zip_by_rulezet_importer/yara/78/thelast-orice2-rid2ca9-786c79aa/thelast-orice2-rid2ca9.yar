rule thelast_orice2_RID2CA9 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file orice2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 09:58:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = " $aa = $_GET['aa'];" 
      $s1 = "echo $aa;" 
   condition: 
      all of them
}
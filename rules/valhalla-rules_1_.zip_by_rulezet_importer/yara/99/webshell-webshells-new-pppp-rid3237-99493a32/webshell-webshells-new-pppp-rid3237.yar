rule Webshell_webshells_new_pppp_RID3237 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file pppp.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:55:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Mail: chinese@hackermail.com" fullword
      $s3 = "if($_GET[\"hackers\"]==\"2b\"){if ($_SERVER['REQUEST_METHOD'] == 'POST') { echo " 
      $s6 = "Site: http://blog.weili.me" fullword
   condition: 
      1 of them
}
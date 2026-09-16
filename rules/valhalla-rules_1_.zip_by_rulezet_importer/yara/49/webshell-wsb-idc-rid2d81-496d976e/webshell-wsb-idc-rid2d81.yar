rule Webshell_wsb_idc_RID2D81 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file idc.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:34:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if (md5($_GET['usr'])==$user && md5($_GET['pass'])==$pass)" fullword
      $s3 = "{eval($_GET['idc']);}" fullword
   condition: 
      1 of them
}
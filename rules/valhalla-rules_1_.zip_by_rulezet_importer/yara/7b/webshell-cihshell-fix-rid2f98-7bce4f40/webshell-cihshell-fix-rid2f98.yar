rule Webshell_cihshell_fix_RID2F98 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file cihshell_fix.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:03:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "<tr style='background:#242424;' ><td style='padding:10px;'><form action='' encty" 
      $s8 = "if (isset($_POST['mysqlw_host'])){$dbhost = $_POST['mysqlw_host'];} else {$dbhos" 
   condition: 
      1 of them
}
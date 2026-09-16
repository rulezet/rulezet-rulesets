rule WebShell_Web_shell__c_ShAnKaR_RID3203 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file Web-shell (c)ShAnKaR.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 13:47:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "header(\"Content-Length: \".filesize($_POST['downf']));" fullword
      $s5 = "if($_POST['save']==0){echo \"<textarea cols=70 rows=10>\".htmlspecialchars($dump" 
      $s6 = "write(\"#\\n#Server : \".getenv('SERVER_NAME').\"" fullword
      $s12 = "foreach(@file($_POST['passwd']) as $fed)echo $fed;" fullword
   condition: 
      2 of them
}
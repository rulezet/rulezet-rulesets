rule Webshell_PHPRemoteView_RID2F95 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file PHPRemoteView.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:03:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "<input type=submit value='\".mm(\"Delete all dir/files recursive\").\" (rm -fr)'" 
      $s4 = "<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u" 
   condition: 
      1 of them
}
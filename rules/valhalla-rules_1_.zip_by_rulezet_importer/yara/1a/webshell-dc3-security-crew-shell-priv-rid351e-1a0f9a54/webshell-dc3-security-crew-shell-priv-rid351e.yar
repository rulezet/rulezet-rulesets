rule WebShell_dC3_Security_Crew_Shell_PRiV_RID351E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file dC3_Security_Crew_Shell_PRiV.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-05 15:59:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "@rmdir($_GET['file']) or die (\"[-]Error deleting dir!\");" fullword
      $s4 = "$ps=str_replace(\"\\\\\",\"/\",getenv('DOCUMENT_ROOT'));" fullword
      $s5 = "header(\"Expires: \".date(\"r\",mktime(0,0,0,1,1,2030)));" fullword
      $s15 = "search_file($_POST['search'],urldecode($_POST['dir']));" fullword
      $s16 = "echo base64_decode($images[$_GET['pic']]);" fullword
      $s20 = "if (isset($_GET['rename_all'])) {" fullword
   condition: 
      3 of them
}
rule WebShell_PhpSpy_Ver_2006_RID2F9D : DEMO T1007 T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file PhpSpy Ver 2006.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:04:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1007, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "var_dump(@$shell->RegRead($_POST['readregname']));" fullword
      $s12 = "$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname." 
      $s19 = "$program = isset($_POST['program']) ? $_POST['program'] : \"c:\\winnt\\system32" 
      $s20 = "$regval = isset($_POST['regval']) ? $_POST['regval'] : 'c:\\winnt\\backdoor.exe'" 
   condition: 
      1 of them
}
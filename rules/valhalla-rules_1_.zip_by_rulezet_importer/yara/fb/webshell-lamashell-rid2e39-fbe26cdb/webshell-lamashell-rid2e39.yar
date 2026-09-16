rule WebShell_lamashell_RID2E39 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file lamashell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:05:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "if(($_POST['exe']) == \"Execute\") {" fullword
      $s8 = "$curcmd = $_POST['king'];" fullword
      $s16 = "\"http://www.w3.org/TR/html4/loose.dtd\">" fullword
      $s18 = "<title>lama's'hell v. 3.0</title>" fullword
      $s19 = "_|_  O    _    O  _|_" 
      $s20 = "$curcmd = \"ls -lah\";" fullword
   condition: 
      2 of them
}
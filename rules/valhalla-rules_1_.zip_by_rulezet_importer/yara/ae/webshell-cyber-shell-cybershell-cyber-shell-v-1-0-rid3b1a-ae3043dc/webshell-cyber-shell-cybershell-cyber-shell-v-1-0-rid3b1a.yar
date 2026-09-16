rule WebShell__Cyber_Shell_cybershell_Cyber_Shell__v_1_0__RID3B1A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - from files Cyber Shell.php, cybershell.php, Cyber Shell (v 1.0).php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 20:14:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "cabf47b96e3b2c46248f075bdbc46197db28a25f"
      hash2 = "9e165d4ed95e0501cd9a90155ac60546eb5b1076"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = " <a href=\"http://www.cyberlords.net\" target=\"_blank\">Cyber Lords Community</" 
      $s10 = "echo \"<meta http-equiv=Refresh content=\\\"0; url=$PHP_SELF?edit=$nameoffile&sh" 
      $s11 = " *   Coded by Pixcher" fullword
      $s16 = "<input type=text size=55 name=newfile value=\"$d/newfile.php\">" fullword
   condition: 
      2 of them
}
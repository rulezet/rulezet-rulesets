rule WEBSHELL_H4ntu_Shell_Powered_Tsoi_2_RID33B4 : DEMO SCRIPT T1033 T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file h4ntu shell [powered by tsoi].php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 14:59:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-03-21"
      tags = "DEMO, SCRIPT, T1033, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<title>h4ntu shell [powered by tsoi]</title>" fullword
      $s2 = "$uname = posix_uname( );" fullword
      $s3 = "if(!$whoami)$whoami=exec(\"whoami\");" fullword
      $s4 = "echo \"<p><font size=2 face=Verdana><b>This Is The Server Information</b></font>" 
   condition: 
      filesize < 2MB and 2 of them
}
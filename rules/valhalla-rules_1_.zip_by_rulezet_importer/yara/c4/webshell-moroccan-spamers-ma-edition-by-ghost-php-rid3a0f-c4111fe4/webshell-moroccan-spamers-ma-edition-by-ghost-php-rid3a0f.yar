rule Webshell_Moroccan_Spamers_Ma_EditioN_By_GhOsT_php_RID3A0F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Moroccan Spamers Ma-EditioN By GhOsT.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 19:30:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = ";$sd98=\"john.barker446@gmail.com\"" 
      $s1 = "print \"Sending mail to $to....... \";" 
      $s2 = "<td colspan=\"2\" width=\"715\" background=\"/simparts/images/cellpic1.gif\" hei" 
   condition: 
      1 of them
}
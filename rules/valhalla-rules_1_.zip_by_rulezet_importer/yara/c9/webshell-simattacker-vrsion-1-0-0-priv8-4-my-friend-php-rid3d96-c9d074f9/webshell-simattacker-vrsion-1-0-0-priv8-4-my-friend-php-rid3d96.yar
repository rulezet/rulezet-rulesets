rule Webshell_SimAttacker___Vrsion_1_0_0___priv8_4_My_friend_php_RID3D96 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 22:00:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "SimAttacker - Vrsion : 1.0.0 - priv8 4 My friend" 
      $s3 = " fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim" 
      $s4 = "echo \"<a target='_blank' href='?id=fm&fedit=$dir$file'><span style='text-decora" 
   condition: 
      1 of them
}
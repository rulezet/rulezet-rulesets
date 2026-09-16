rule Webshell_SimAttacker_Vrsion_1_0_0_priv8_4_My_friend_RID3A73 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 19:47:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "echo \"<a href='?id=fm&fchmod=$dir$file'><span style='text-decoration: none'><fo" 
      $s3 = "fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim" 
   condition: 
      1 of them
}
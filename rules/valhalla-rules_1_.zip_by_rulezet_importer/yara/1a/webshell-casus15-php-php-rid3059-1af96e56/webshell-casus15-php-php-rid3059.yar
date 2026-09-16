rule Webshell_Casus15_php_php_RID3059 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Casus15.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:36:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "copy ( $dosya_gonder2, \"$dir/$dosya_gonder2_name\") ? print(\"$dosya_gonder2_na" 
      $s2 = "echo \"<center><font size='$sayi' color='#FFFFFF'>HACKLERIN<font color='#008000'" 
      $s3 = "value='Calistirmak istediginiz " 
   condition: 
      1 of them
}
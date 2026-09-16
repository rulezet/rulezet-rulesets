rule Webshell_aZRaiLPhp_v1_0_RID2F86 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file aZRaiLPhp v1.0.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:00:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "echo \" <font color='#0000FF'>CHMODU \".substr(base_convert(@fileperms($" 
      $s7 = "echo \"<a href='./$this_file?op=efp&fname=$path/$file&dismi=$file&yol=$path'><fo" 
   condition: 
      all of them
}
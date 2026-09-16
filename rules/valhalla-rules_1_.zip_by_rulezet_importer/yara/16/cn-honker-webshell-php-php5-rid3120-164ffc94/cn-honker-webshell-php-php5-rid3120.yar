rule CN_Honker_Webshell_PHP_php5_RID3120 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php5.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:09:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "else if(isset($_POST['reverse'])) { if(@ftp_login($connection,$user,strrev($user" ascii
      $s20 = "echo sr(35,in('hidden','dir',0,$dir).in('hidden','cmd',0,'mysql_dump').\"<b>\".$" ascii
   condition: 
      uint16 ( 0 ) == 0x3f3c and filesize < 300KB and all of them
}
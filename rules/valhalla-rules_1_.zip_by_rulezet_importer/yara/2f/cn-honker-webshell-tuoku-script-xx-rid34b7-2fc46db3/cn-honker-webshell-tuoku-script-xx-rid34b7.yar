rule CN_Honker_Webshell_Tuoku_script_xx_RID34B7 : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file xx.php"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:42:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$mysql.=\"insert into `$table`($keys) values($vals);\\r\\n\";" fullword ascii
      $s2 = "$mysql_link=@mysql_connect($mysql_servername , $mysql_username , $mysql_password" ascii
      $s16 = "mysql_query(\"SET NAMES gbk\");" fullword ascii
   condition: 
      filesize < 2KB and all of them
}
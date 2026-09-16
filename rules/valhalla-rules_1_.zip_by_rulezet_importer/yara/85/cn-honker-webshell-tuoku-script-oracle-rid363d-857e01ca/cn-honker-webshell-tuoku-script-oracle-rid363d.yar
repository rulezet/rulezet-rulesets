rule CN_Honker_Webshell_Tuoku_script_oracle_RID363D : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file oracle.jsp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 16:47:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";" fullword ascii
      $s2 = "String user=\"oracle_admin\";" fullword ascii
      $s3 = "String sql=\"SELECT 1,2,3,4,5,6,7,8,9,10 from user_info\";" fullword ascii
   condition: 
      filesize < 7KB and all of them
}
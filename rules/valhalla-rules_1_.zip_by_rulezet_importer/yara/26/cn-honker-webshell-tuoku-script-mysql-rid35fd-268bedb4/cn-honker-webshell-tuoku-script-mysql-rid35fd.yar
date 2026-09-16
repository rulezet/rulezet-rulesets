rule CN_Honker_Webshell_Tuoku_script_mysql_RID35FD : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file mysql.aspx"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 16:36:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "txtpassword.Attributes.Add(\"onkeydown\", \"SubmitKeyClick('btnLogin');\");" fullword ascii
      $s2 = "connString = string.Format(\"Host = {0}; UserName = {1}; Password = {2}; Databas" ascii
   condition: 
      filesize < 202KB and all of them
}
rule CN_Honker_Webshell_su7_x_9_x_RID31C1 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file su7.x-9.x.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:36:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "returns=httpopen(\"LoginID=\"&user&\"&FullName=&Password=\"&pass&\"&ComboPasswor" ascii
      $s1 = "returns=httpopen(\"\",\"POST\",\"http://127.0.0.1:\"&port&\"/Admin/XML/User.xml?" ascii
   condition: 
      filesize < 59KB and all of them
}
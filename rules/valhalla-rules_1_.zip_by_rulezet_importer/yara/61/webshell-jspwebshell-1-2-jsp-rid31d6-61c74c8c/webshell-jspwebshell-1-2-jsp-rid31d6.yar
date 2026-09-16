rule Webshell_JspWebshell_1_2_jsp_RID31D6 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file JspWebshell 1.2.jsp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:39:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "JspWebshell" 
      $s1 = "CreateAndDeleteFolder is error:" 
      $s2 = "<td width=\"70%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.c" 
      $s3 = "String _password =\"111\";" 
   condition: 
      2 of them
}
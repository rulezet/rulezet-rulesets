rule Webshell_JFolder_jfolder01_jsp_leo_RID343D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 400.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, warn.jsp, webshell-nc.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:22:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "793b3d0a740dbf355df3e6f68b8217a4"
      hash2 = "8979594423b68489024447474d113894"
      hash3 = "ec482fc969d182e5440521c913bab9bd"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "sbFolder.append(\"<tr><td >&nbsp;</td><td>\");" fullword
      $s1 = "return filesize / intDivisor + \".\" + strAfterComma + \" \" + strUnit;" fullword
      $s5 = "FileInfo fi = (FileInfo) ht.get(\"cqqUploadFile\");" fullword
      $s6 = "<input type=\"hidden\" name=\"cmd\" value=\"<%=strCmd%>\">" fullword
   condition: 
      2 of them
}
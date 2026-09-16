rule Webshell_in_JFolder_jfolder01_jsp_leo_warn_RID378A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, warn.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 17:42:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8979594423b68489024447474d113894"
      hash2 = "ec482fc969d182e5440521c913bab9bd"
      hash3 = "f98d2b33cd777e160d1489afed96de39"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('down','\"+formatPath(strD" 
      $s9 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('edit','\"+formatPath(strDi" 
   condition: 
      all of them
}
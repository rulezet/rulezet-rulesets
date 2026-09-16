rule Webshell_JFolder_jfolder01_xxx_RID32B9 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 404.jsp, data.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, suiyue.jsp, warn.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:17:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
      hash2 = "793b3d0a740dbf355df3e6f68b8217a4"
      hash3 = "8979594423b68489024447474d113894"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "&nbsp;<TEXTAREA NAME=\"cqq\" ROWS=\"20\" COLS=\"100%\"><%=sbCmd.toString()%></TE" 
   condition: 
      all of them
}
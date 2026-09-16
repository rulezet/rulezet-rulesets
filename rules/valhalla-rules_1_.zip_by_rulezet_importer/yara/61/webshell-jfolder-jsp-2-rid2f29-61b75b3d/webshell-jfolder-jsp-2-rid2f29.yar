rule Webshell_JFolder_JSP_2_RID2F29 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 404.jsp, data.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, suiyue.jsp, warn.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:45:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
      hash2 = "793b3d0a740dbf355df3e6f68b8217a4"
      hash3 = "8979594423b68489024447474d113894"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<table width=\"100%\" border=\"1\" cellspacing=\"0\" cellpadding=\"5\" bordercol" 
      $s2 = " KB </td>" fullword
      $s3 = "<table width=\"98%\" border=\"0\" cellspacing=\"0\" cellpadding=\"" 
      $s4 = "<!-- <tr align=\"center\"> " fullword
   condition: 
      all of them
}
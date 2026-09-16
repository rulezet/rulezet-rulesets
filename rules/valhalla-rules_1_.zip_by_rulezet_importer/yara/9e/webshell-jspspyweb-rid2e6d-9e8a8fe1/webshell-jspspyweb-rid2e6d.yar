rule Webshell_Jspspyweb_RID2E6D : DEMO SCRIPT T1112 T1505_003 T1543_003 WEBSHELL {
   meta:
      description = "Web Shell - file Jspspyweb.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:14:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1112, T1505_003, T1543_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "      out.print(\"<tr><td width='60%'>\"+strCut(convertPath(list[i].getPath()),7" 
      $s3 = "  \"reg add \\\"HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control" 
   condition: 
      all of them
}
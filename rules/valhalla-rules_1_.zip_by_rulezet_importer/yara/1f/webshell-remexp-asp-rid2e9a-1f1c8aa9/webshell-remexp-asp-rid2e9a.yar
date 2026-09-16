rule Webshell_RemExp_asp_RID2E9A : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file RemExp.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:21:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<title>Remote Explorer</title>" 
      $s3 = " FSO.CopyFile Request.QueryString(\"FolderPath\") & Request.QueryString(\"CopyFi" 
      $s4 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f" 
   condition: 
      2 of them
}
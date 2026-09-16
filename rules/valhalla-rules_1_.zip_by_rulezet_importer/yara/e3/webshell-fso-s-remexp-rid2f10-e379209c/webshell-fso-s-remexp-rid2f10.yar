rule Webshell_FSO_s_RemExp_RID2F10 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file RemExp.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:41:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Request.Ser" 
      $s5 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f=<%=F" 
      $s6 = "<td bgcolor=\"<%=BgColor%>\" align=\"right\"><%=Attributes(SubFolder.Attributes)%></" 
   condition: 
      all of them
}
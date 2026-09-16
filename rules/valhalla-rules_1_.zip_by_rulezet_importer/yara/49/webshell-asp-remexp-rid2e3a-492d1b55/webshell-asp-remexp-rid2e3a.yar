rule Webshell_ASP_RemExp_RID2E3A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file RemExp.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:05:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Reques" 
      $s1 = "Private Function ConvertBinary(ByVal SourceNumber, ByVal MaxValuePerIndex, ByVal" 
   condition: 
      all of them
}
rule Webshell_ASP_tool_RID2DA7 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file tool.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:41:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Response.Write \"<FORM action=\"\"\" & Request.ServerVariables(\"URL\") & \"\"\"" 
      $s3 = "Response.Write \"<tr><td><font face='arial' size='2'><b>&lt;DIR&gt; <a href='\" " 
      $s9 = "Response.Write \"<font face='arial' size='1'><a href=\"\"#\"\" onclick=\"\"javas" 
   condition: 
      2 of them
}
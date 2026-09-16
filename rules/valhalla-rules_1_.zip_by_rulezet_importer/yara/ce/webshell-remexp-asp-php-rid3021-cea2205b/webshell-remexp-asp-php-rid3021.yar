rule WebShell_RemExp_asp_php_RID3021 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file RemExp.asp.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-05 12:26:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "lsExt = Right(FileName, Len(FileName) - liCount)" fullword
      $s7 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f" 
      $s13 = "Response.Write Drive.ShareName & \" [share]\"" fullword
      $s19 = "If Request.QueryString(\"CopyFile\") <> \"\" Then" fullword
      $s20 = "<td width=\"40%\" height=\"20\" bgcolor=\"silver\">  Name</td>" fullword
   condition: 
      all of them
}
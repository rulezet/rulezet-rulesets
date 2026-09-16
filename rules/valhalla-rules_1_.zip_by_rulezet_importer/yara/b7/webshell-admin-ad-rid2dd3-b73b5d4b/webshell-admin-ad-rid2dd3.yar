rule Webshell_admin_ad_RID2DD3 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file admin-ad.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 10:48:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s6 = "<td align=\"center\"> <input name=\"cmd\" type=\"text\" id=\"cmd\" siz" 
      $s7 = "Response.write\"<a href='\"&url&\"?path=\"&Request(\"oldpath\")&\"&attrib=\"&attrib&\"'><" 
   condition: 
      all of them
}
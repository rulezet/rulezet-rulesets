rule Webshell_aspbackdoor_EDIR_RID30B2 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Disclosed hacktool set (old stuff) - file EDIR.ASP"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 12:50:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "response.write \"<a href='index.asp'>" fullword ascii
      $s3 = "if Request.Cookies(\"password\")=\"" ascii
      $s6 = "whichdir=server.mappath(Request(\"path\"))" fullword ascii
      $s7 = "Set fs = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $s19 = "whichdir=Request(\"path\")" fullword ascii
   condition: 
      all of them
}
rule Webshell_aspbackdoor_asp3_RID3105 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Disclosed hacktool set (old stuff) - file asp3.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 13:04:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<form action=\"changepwd.asp\" method=\"post\"> " fullword ascii
      $s1 = "  Set oUser = GetObject(\"WinNT://ComputerName/\" & UserName) " fullword ascii
      $s2 = "    value=\"<%=Request.ServerVariables(\"LOGIN_USER\")%>\"> " fullword ascii
      $s14 = " Windows NT " fullword ascii
      $s16 = " WIndows 2000 " fullword ascii
      $s18 = "OldPwd = Request.Form(\"OldPwd\") " fullword ascii
      $s19 = "NewPwd2 = Request.Form(\"NewPwd2\") " fullword ascii
      $s20 = "NewPwd1 = Request.Form(\"NewPwd1\") " fullword ascii
   condition: 
      all of them
}
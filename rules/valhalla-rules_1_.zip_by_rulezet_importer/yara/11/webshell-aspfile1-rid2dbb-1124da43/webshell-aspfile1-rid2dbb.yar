rule Webshell_aspfile1_RID2DBB : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Disclosed hacktool set (old stuff) - file aspfile1.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 10:44:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "' -- check for a command that we have posted -- '" fullword ascii
      $s1 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword ascii
      $s5 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\"><BODY>" fullword ascii
      $s6 = "<input type=text name=\".CMD\" size=45 value=\"<%= szCMD %>\">" fullword ascii
      $s8 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword ascii
      $s15 = "szCMD = Request.Form(\".CMD\")" fullword ascii
   condition: 
      3 of them
}
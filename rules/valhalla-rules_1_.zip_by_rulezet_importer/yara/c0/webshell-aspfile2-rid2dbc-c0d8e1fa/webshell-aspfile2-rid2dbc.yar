rule Webshell_aspfile2_RID2DBC : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Disclosed hacktool set (old stuff) - file aspfile2.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 10:44:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "response.write \"command completed success!\" " fullword ascii
      $s1 = "for each co in foditems " fullword ascii
      $s3 = "<input type=text name=text6 value=\"<%= szCMD6 %>\"><br> " fullword ascii
      $s19 = "<title>Hello! Welcome </title>" fullword ascii
   condition: 
      all of them
}
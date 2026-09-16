rule CN_Honker_Alien_D_RID2D53 : CHINA DEMO SCRIPT SUSP {
   meta:
      description = "Script from disclosed CN Honker Pentest Toolset - file D.ASP"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 10:27:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Paths_str=\"c:\\windows\\\"&chr(13)&chr(10)&\"c:\\Documents and Settings\\\"&chr" ascii
      $s1 = "CONST_FSO=\"Script\"&\"ing.Fil\"&\"eSyst\"&\"emObject\"" fullword ascii
      $s2 = "Response.Write \"<form id='form1' name='form1' method='post' action=''>\"" fullword ascii
      $s3 = "set getAtt=FSO.GetFile(filepath)" fullword ascii
      $s4 = "Response.Write \"<input name='NoCheckTemp' type='checkbox' id='NoCheckTemp' chec" ascii
   condition: 
      filesize < 30KB and 2 of them
}
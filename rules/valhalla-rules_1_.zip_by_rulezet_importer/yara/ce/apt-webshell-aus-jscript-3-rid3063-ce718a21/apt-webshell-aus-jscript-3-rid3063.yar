rule APT_WebShell_AUS_JScript_3_RID3063 : APT DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18 12:37:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7ac6f973f7fccf8c3d58d766dec4ab7eb6867a487aa71bc11d5f05da9322582d"
      tags = "APT, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<%@ Page Language=\"Jscript\" validateRequest=\"false\"%><%try{eval(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String" ascii
      $s2 = ".Item[\"[password]\"])),\"unsafe\");}" ascii
   condition: 
      uint16 ( 0 ) == 0x6568 and filesize < 1KB and all of them
}
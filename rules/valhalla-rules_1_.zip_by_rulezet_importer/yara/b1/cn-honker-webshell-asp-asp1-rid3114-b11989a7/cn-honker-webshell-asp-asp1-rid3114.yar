rule CN_Honker_Webshell_ASP_asp1_RID3114 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file asp1.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:07:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "SItEuRl=" ascii
      $s2 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii
      $s3 = "Server.ScriptTimeout=" ascii
   condition: 
      filesize < 200KB and all of them
}
rule CN_Honker_Webshell_ASPX_shell_shell_RID3486 : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file shell.aspx"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:34:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%try{ System.Reflection.Assembly.Load(Request.BinaryRead(int.Parse(Request.Cook" ascii
      $s1 = "<%@ Page Language=\"C#\" ValidateRequest=\"false\" %>" fullword ascii
   condition: 
      filesize < 1KB and all of them
}
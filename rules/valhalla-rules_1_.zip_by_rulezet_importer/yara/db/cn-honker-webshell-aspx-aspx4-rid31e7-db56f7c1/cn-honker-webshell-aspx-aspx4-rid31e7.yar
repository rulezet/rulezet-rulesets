rule CN_Honker_Webshell_ASPX_aspx4_RID31E7 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file aspx4.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:42:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "File.Delete(cdir.FullName + \"\\\\test\");" fullword ascii
      $s5 = "start<asp:TextBox ID=\"Fport_TextBox\" runat=\"server\" Text=\"c:\\\" Width=\"60" ascii
      $s6 = "<div>Code By <a href =\"http://www.hkmjj.com\">Www.hkmjj.Com</a></div>" fullword ascii
   condition: 
      filesize < 11KB and all of them
}
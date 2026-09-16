rule CN_Honker_Webshell_ASPX_aspx_RID31B3 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file aspx.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:33:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "string iVDT=\"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin" ascii
      $s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii
      $s2 = "td.Text=\"<a href=\\\"javascript:Bin_PostBack('urJG','\"+dt.Rows[j][\"ProcessID" ascii
      $s3 = "vyX.Text+=\"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\"+MVVJ(rootkey)+" ascii
   condition: 
      filesize < 353KB and 2 of them
}
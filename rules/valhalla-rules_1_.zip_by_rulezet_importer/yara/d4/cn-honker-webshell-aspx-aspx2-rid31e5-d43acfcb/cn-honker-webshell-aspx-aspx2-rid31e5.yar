rule CN_Honker_Webshell_ASPX_aspx2_RID31E5 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file aspx2.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:42:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "if (password.Equals(this.txtPass.Text))" fullword ascii
      $s1 = "<head runat=\"server\">" fullword ascii
      $s2 = ":<asp:TextBox runat=\"server\" ID=\"txtPass\" Width=\"400px\"></asp:TextBox>" fullword ascii
      $s3 = "this.lblthispath.Text = Server.MapPath(Request.ServerVariables[\"PATH_INFO\"]);" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 9KB and all of them
}
rule Nishang_Webshell_RID2D6E : DEMO FILE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a ASPX web shell"
      author = "Florian Roth"
      reference = "https://github.com/samratashok/nishang"
      date = "2016-09-11 10:31:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "psi.Arguments = \"-noninteractive \" + \"-executionpolicy bypass \" + arg;" ascii
      $s2 = "output.Text += \"\nPS> \" + console.Text + \"\n\" + do_ps(console.Text);" ascii
      $s3 = "<title>Antak Webshell</title>" fullword ascii
      $s4 = "<asp:Button ID=\"executesql\" runat=\"server\" Text=\"Execute SQL Query\"" ascii
   condition: 
      ( uint16 ( 0 ) == 0x253C and filesize < 100KB and 1 of ( $s* ) )
}
rule WEBSHELL_ASPX_Sharepoint_Drop_CVE_2025_53770_Jul25_RID372D : CVE_2025_53770 DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects ASPX web shell dropped during the exploitation of SharePoint RCE vulnerability CVE-2025-53770"
      author = "Florian Roth"
      reference = "https://research.eye.security/sharepoint-under-siege/"
      date = "2025-07-20 17:27:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2025_53770, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "var sy = System.Reflection.Assembly.Load(" ascii
      $x2 = "Response.Write(cg.ValidationKey+" ascii
      $s1 = "<script runat=\"server\" language=\"c#\" CODEPAGE=\"65001\">" ascii fullword
   condition: 
      filesize < 4KB and 1 of ( $x* ) or all of them
}
rule WEBSHELL_ASPX_Compiled_Sharepoint_Drop_CVE_2025_53770_Jul25_2_RID3B4A : CVE_2025_53770 DEMO EXE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects compiled ASPX web shell dropped during the exploitation of SharePoint RCE vulnerability CVE-2025-53770"
      author = "Florian Roth, Marius Benthin"
      reference = "https://research.eye.security/sharepoint-under-siege/"
      date = "2025-07-20 20:22:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-07-25"
      tags = "CVE_2025_53770, DEMO, EXE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = /App_Web_spinstall\d{0,1}.aspx/ wide
      $x2 = /spinstall[\w]?[\._]aspx/ ascii
      $x3 = /\/_layouts\/1[0-9]\/spinstall/ wide
      $x4 = /\/_layouts\/1[0-9]\/ghostfile/ wide
      $s1 = "System.Web.Configuration.MachineKeySection" wide
      $s2 = "Page_load" ascii fullword
      $s3 = "GetApplicationConfig" wide fullword
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 20KB and ( 1 of ( $x* ) or all of ( $s* ) ) or 2 of ( $x* ) or 4 of them
}
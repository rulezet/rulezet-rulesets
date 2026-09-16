rule WEBSHELL_ASPX_Compiled_Sharepoint_Drop_CVE_2025_53770_Jul25_2 {
   meta:
      description = "Detects compiled ASPX web shell dropped during the exploitation of SharePoint RCE vulnerability CVE-2025-53770"
      author = "Florian Roth, Marius Benthin"
      reference = "https://research.eye.security/sharepoint-under-siege/"
      date = "2025-07-20"
      modified = "2025-07-25"
      score = 75
      hash = "8d3d3f3a17d233bc8562765e61f7314ca7a08130ac0fb153ffd091612920b0f2"
      hash = "d8ca5e5d6400ac34ac4cc138efa89d2ec4d5c0e968a78fa3ba5dbc04c7550649"
      hash = "7e9b77da1f51d03ee2f96bc976f6aeb781f801cf633862a4b8c356cbb555927d"
   strings:
      $x1 = /App_Web_spinstall\d{0,1}.aspx/ wide
      $x2 = /spinstall[\w]?[\._]aspx/ ascii
      $x3 = /\/_layouts\/1[0-9]\/spinstall/ wide
      $x4 = /\/_layouts\/1[0-9]\/ghostfile/ wide

      $s1 = "System.Web.Configuration.MachineKeySection" wide
      $s2 = "Page_load" ascii fullword
      $s3 = "GetApplicationConfig" wide fullword
   condition:
      uint16(0) == 0x5a4d
      and filesize < 20KB
      and (
         1 of ($x*)
         or all of ($s*)
      )
      or 2 of ($x*)
      or 4 of them
}
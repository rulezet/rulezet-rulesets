rule APT_EXPL_Sharepoint_CVE_2025_53770_ForensicArtefact_Jul25_1_RID3B17 : APT CVE_2025_53770 DEMO EXPLOIT {
   meta:
      description = "Detects URIs accessed during the exploitation of SharePoint RCE vulnerability CVE-2025-53770"
      author = "Florian Roth"
      reference = "https://research.eye.security/sharepoint-under-siege/"
      date = "2025-07-20 20:14:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-07-23"
      tags = "APT, CVE_2025_53770, DEMO, EXPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $sa1 = /POST \/_layouts\/1[0-9]\/ToolPane\.aspx/ ascii wide nocase
      $sa2 = "DisplayMode=Edit&a=/ToolPane.aspx" ascii wide
      $sb1 = /GET \/_layouts\/1[0-9]\/spinstall/ ascii wide
      $sb2 = "/_layouts/SignOut.aspx 200" ascii wide nocase
   condition: 
      ( @sa2 - @sa1 ) < 700 or ( @sb2 - @sb1 ) < 700 or ( @sb2 - @sa1 ) < 700
}
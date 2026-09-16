rule APT_HAFNIUM_ForensicArtefacts_WER_Mar21_1_RID3551 : APT CVE_2021_26857 DEMO FILE G0125 {
   meta:
      description = "Detects a Windows Error Report (WER) that indicates and exploitation attempt of the Exchange server as described in CVE-2021-26857 after the corresponding patches have been applied. WER files won't be written upon successful exploitation before applying the patch. Therefore, this indicates an unsuccessful attempt."
      author = "Florian Roth"
      reference = "https://twitter.com/cyb3rops/status/1368471533048446976"
      date = "2021-03-07 16:08:01"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, CVE_2021_26857, DEMO, FILE, G0125"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "AppPath=c:\\windows\\system32\\inetsrv\\w3wp.exe" wide fullword
      $s7 = ".Value=w3wp#MSExchangeECPAppPool" wide
   condition: 
      uint16 ( 0 ) == 0xfeff and filesize < 8KB and all of them
}
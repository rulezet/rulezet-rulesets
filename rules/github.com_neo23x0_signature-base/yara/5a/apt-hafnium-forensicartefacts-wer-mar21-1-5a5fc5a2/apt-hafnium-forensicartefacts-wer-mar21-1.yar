rule APT_HAFNIUM_ForensicArtefacts_WER_Mar21_1 {
   meta:
      description = "Detects a Windows Error Report (WER) that indicates and exploitation attempt of the Exchange server as described in CVE-2021-26857 after the corresponding patches have been applied. WER files won't be written upon successful exploitation before applying the patch. Therefore, this indicates an unsuccessful attempt."
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyb3rops/status/1368471533048446976"
      date = "2021-03-07"
      score = 40
      id = "06771101-10ce-5d6b-99f7-a321aade7f69"
   strings:
      $s1 = "AppPath=c:\\windows\\system32\\inetsrv\\w3wp.exe" wide fullword
      $s7 = ".Value=w3wp#MSExchangeECPAppPool" wide
   condition:
      uint16(0) == 0xfeff and
      filesize < 8KB and
      all of them
}
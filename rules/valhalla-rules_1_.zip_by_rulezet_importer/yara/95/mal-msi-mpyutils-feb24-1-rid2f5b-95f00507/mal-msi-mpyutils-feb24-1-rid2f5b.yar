rule MAL_MSI_Mpyutils_Feb24_1_RID2F5B : CVE_2024_1708 CVE_2024_1709 DEMO FILE MAL {
   meta:
      description = "Detects malicious MSI package mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23 11:53:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8e51de4774d27ad31a83d5df060ba008148665ab9caf6bc889a5e3fba4d7e600"
      tags = "CVE_2024_1708, CVE_2024_1709, DEMO, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "crypt64ult.exe" ascii fullword
      $s2 = "EXPAND.EXE" wide fullword
      $s6 = "ICACLS.EXE" wide fullword
   condition: 
      uint16 ( 0 ) == 0xcfd0 and filesize < 20000KB and all of them
}
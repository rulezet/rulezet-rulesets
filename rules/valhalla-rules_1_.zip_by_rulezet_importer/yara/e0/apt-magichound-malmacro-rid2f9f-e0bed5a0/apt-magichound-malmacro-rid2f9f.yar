rule APT_MagicHound_MalMacro_RID2F9F : APT DEMO FILE G0059 OFFICE SCRIPT T1059_001 T1203 T1566_001 {
   meta:
      description = "Detects malicious macro / powershell in Office document"
      author = "Florian Roth"
      reference = "https://www.secureworks.com/blog/iranian-pupyrat-bites-middle-eastern-organizations"
      date = "2017-02-17 12:05:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "66d24a529308d8ab7b27ddd43a6c2db84107b831257efb664044ec4437f9487b"
      hash2 = "e5b643cb6ec30d0d0b458e3f2800609f260a5f15c4ac66faf4ebf384f7976df6"
      tags = "APT, DEMO, FILE, G0059, OFFICE, SCRIPT, T1059_001, T1203, T1566_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "powershell.exe " fullword ascii
      $s2 = "CommandButton1_Click" fullword ascii
      $s3 = "URLDownloadToFile" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0xcfd0 and filesize < 8000KB and all of them )
}
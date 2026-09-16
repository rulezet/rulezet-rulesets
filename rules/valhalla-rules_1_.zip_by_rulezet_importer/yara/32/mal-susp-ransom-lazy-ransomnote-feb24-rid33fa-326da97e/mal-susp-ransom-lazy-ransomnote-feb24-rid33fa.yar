rule MAL_SUSP_RANSOM_Lazy_RansomNote_Feb24_RID33FA : CRIME DEMO MAL RANSOM SUSP {
   meta:
      description = "Detects the Lazy ransom note file 'HowToRestoreYourFiles.txt' which is a sign of a Lazy ransomware infection"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23 15:10:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CRIME, DEMO, MAL, RANSOM, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "All Encrypted files can be reversed to original form and become usable" 
   condition: 
      1 of them
}
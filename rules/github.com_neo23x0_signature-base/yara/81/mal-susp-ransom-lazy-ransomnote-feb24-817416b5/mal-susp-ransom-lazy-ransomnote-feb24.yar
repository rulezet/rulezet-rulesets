rule MAL_SUSP_RANSOM_Lazy_RansomNote_Feb24 {
   meta:
      description = "Detects the Lazy ransom note file 'HowToRestoreYourFiles.txt' which is a sign of a Lazy ransomware infection"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23"
      score = 75
      id = "287dfd67-8d0d-5906-b593-3af42a5a3aa4"
   strings:
      $x1 = "All Encrypted files can be reversed to original form and become usable"
   condition:
      1 of them
}
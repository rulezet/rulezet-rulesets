rule MAL_SUSP_RANSOM_LockBit_RansomNote_Feb24_RID3502 : CRIME DEMO LockBit MAL RANSOM SUSP {
   meta:
      description = "Detects the LockBit ransom note file 'LockBit-DECRYPT.txt' which is a sign of a LockBit ransomware infection"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23 15:54:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CRIME, DEMO, LockBit, MAL, RANSOM, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = ">>>> Your personal DECRYPTION ID:" 
   condition: 
      1 of them
}
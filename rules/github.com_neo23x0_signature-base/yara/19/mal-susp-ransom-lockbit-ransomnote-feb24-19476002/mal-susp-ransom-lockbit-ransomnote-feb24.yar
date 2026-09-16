rule MAL_SUSP_RANSOM_LockBit_RansomNote_Feb24 {
   meta:
      description = "Detects the LockBit ransom note file 'LockBit-DECRYPT.txt' which is a sign of a LockBit ransomware infection"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23"
      score = 75
      id = "b2fcb2a7-49e8-520c-944f-6acd5ded579b"
   strings:
      $x1 = ">>>> Your personal DECRYPTION ID:"
   condition:
      1 of them
}
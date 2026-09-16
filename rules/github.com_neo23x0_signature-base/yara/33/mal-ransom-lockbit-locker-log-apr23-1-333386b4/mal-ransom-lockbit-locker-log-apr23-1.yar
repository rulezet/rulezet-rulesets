rule MAL_RANSOM_LockBit_Locker_LOG_Apr23_1 {
   meta:
      description = "Detects indicators found in LockBit ransomware log files"
      author = "Florian Roth"
      reference = "https://objective-see.org/blog/blog_0x75.html"
      date = "2023-04-17"
      score = 75
      id = "aa0a2393-e5a2-5151-8afb-91a9bb922179"
   strings:
      $s1 = " is encrypted. Checksum after encryption "
      $s2 = "~~~~~Hardware~~~~"
      $s3 = "[+] Add directory to encrypt:"
      $s4 = "][+] Launch parameters: "
   condition:
      2 of them
}
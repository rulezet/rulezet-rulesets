rule MAL_RANSOM_LockBit_Apr23_1 {
   meta:
      description = "Detects indicators found in LockBit ransomware"
      author = "Florian Roth"
      reference = "https://objective-see.org/blog/blog_0x75.html"
      date = "2023-04-17"
      score = 75
      id = "75dc8b95-16f0-5170-a7d6-fc10bb778348"
   strings:
      $xe1 = "-i '/path/to/crypt'" xor
      $xe2 = "http://lockbit" xor
      
      $s1 = "idelayinmin" ascii
      $s2 = "bVMDKmode" ascii
      $s3 = "bSelfRemove" ascii
      $s4 = "iSpotMaximum" ascii

      $fp1 = "<html"
   condition:
      (
         1 of ($x*)
         or 4 of them
      )
      and not 1 of ($fp*)
}
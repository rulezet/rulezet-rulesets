rule MAL_RANSOM_LockBit_Locker_LOG_Apr23_1_RID3398 : CRIME DEMO LOG LockBit MAL RANSOM {
   meta:
      description = "Detects indicators found in LockBit ransomware log files"
      author = "Florian Roth"
      reference = "https://objective-see.org/blog/blog_0x75.html"
      date = "2023-04-17 14:54:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CRIME, DEMO, LOG, LockBit, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = " is encrypted. Checksum after encryption " 
      $s2 = "~~~~~Hardware~~~~" 
      $s3 = "[+] Add directory to encrypt:" 
      $s4 = "][+] Launch parameters: " 
   condition: 
      2 of them
}
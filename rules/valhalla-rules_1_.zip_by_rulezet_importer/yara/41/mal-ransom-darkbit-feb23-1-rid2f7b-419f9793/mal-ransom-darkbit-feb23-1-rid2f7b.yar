rule MAL_RANSOM_DarkBit_Feb23_1_RID2F7B : CRIME DEMO DarkBit EXE FILE MAL RANSOM {
   meta:
      description = "Detects indicators found in DarkBit ransomware"
      author = "Florian Roth"
      reference = "https://twitter.com/idonaor1/status/1624703255770005506?s=12&t=mxHaauzwR6YOj5Px8cIeIw"
      date = "2023-02-13 11:59:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CRIME, DEMO, DarkBit, EXE, FILE, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ".onion" ascii
      $s2 = "GetMOTWHostUrl" 
      $x1 = "hus31m7c7ad.onion" 
      $x2 = "iw6v2p3cruy" 
      $xn1 = "You will receive decrypting key after the payment." 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 10MB and ( 1 of ( $x* ) or 2 of them ) or 4 of them or ( filesize < 10MB and $xn1 )
}
rule SUSP_Nimbus_Manticore_PDF_Indicators_May26 {
   meta:
      description = "Detects inidcators found in PDF files created by Nimbus Manticore (UNC1549). The PDF files usually contain fake job offers or descriptions to lure victims into installing malware."
      author = "Jonathan Peters (Nextron Systems)"
      date = "2026-05-25"
      reference = "https://www.nextron-systems.com/2026/06/01/detecting-nimbus-manticore-and-their-sideloading-infection-chains/"
      hash = "620c51f4376cb79f0109c21971c28661418ae50b119585e3ffdb8011189fcb7b"
      score = 70
   strings:
      $op = { 3C 3C 2F 41 75 74 68 6F 72 28 4A 65 72 72 79 29 20 2F 43 72 65 61 74 6F 72 28 FE FF 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 AE 00 20 00 57 00 6F 00 72 00 64 00 20 00 4C 00 54 00 53 00 43 29 }
   condition:
      1 of them
}
rule Molerats_Jul17_Sample_1_RID2F9B : APT DEMO EXE FILE G0021 {
   meta:
      description = "Detects Molerats sample - July 2017"
      author = "Florian Roth"
      reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
      date = "2017-07-07 12:04:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ebf2423b9de131eab1c61ac395cbcfc2ac3b15bd9c83b96ae0a48619a4a38d0a"
      tags = "APT, DEMO, EXE, FILE, G0021"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ezExODA0Y2U0LTkzMGEtNGIwOS1iZjcwLTlmMWE5NWQwZDcwZH0sIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49M2U1NjM1MDY5M2Y3MzU1ZQ==,[z]{c00" wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}
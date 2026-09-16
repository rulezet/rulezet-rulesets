rule MAL_APT_NK_Andariel_Agni {
   meta:
      author = "CISA.gov"
      description = "Detects samples of the Agni malware family"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 80
      id = "ffe3f427-c10a-5ad4-ab29-c0d9b576c30f"
   strings:
      $xor = { 34 ?? 88 01 48 8D 49 01 0F B6 01 84 C0 75 F1 }
      $stackstrings = { C7 44 24 [5-10] C7 44 24 [5] C7 44 24 [5-10] C7 44 24 [5-10] C7 44 24 }
   condition:
      uint16(0) == 0x5a4d 
      and #xor > 100 
      and #stackstrings > 5
}
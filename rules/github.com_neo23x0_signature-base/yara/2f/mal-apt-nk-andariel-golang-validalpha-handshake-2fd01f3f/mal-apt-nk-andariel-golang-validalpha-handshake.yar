rule MAL_APT_NK_Andariel_GoLang_Validalpha_Handshake {
   meta:
      author = "CISA.gov"
      description = "Detects a variant of the GoLang Validalpha malware"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 75
      id = "51dafa43-9da0-569a-9123-7e9800284046"
   strings:
      $ = { 66 C7 00 AB CD C6 40 02 EF ?? 03 00 00 00 48 89 C1 ?? 03 00 00 00 }
   condition:
      all of them
}
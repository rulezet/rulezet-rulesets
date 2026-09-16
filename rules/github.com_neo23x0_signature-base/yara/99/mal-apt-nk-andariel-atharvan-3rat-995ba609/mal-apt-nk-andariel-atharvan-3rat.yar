rule MAL_APT_NK_Andariel_Atharvan_3RAT {
   meta:
      author = "CISA.gov"
      description = "Detects a variant of the Atharvan 3RAT malware family"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 80
      id = "9ff6998a-a2dd-5671-bd3f-ee69561f71ef"
   strings:
      $3RAT = "D:\\rang\\TOOL\\3RAT" 
      $atharvan = "Atharvan_dll.pdb"
   condition:
      uint16(0) == 0x5a4d 
      and 1 of them
}
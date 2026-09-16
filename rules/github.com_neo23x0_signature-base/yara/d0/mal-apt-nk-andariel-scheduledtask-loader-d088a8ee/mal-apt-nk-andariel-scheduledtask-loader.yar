rule MAL_APT_NK_Andariel_ScheduledTask_Loader {
   meta:
      author = "CISA.gov"
      description = "Detects a scheduled task loader used by Andariel"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 80
      id = "0c32758b-480c-5784-b28f-cee85d038850"
   strings:
      $obfuscation1 = { B8 02 00 00 00 48 6B C0 00 B9 CD FF 00 00 66 89 8C 04 60 01 00 00 B8 02 00 00 00 48 6B C0 01 B9 CC FF 00 00 66 89 8C 04 60 01 00 00 B8 02 00 00 00 48 6B C0 02 B9 8D FF 00 00 66 89 8C 04 60 01 00 00 B8 02 00 00 00 48 6B C0 03 B9 9A FF 00 00 66 89 8C 04 60 01 00 00 B8 02 00 00 00 48 6B C0 04 B9 8C FF 00 00 66 89 8C 04 60 01 00 00 B8 02 00 00 00 48 6B C0 05 B9 8A FF 00 00 66 89 8C 04 60 01 00 00 B8 02 00 00 00 48 6B C0 06 33 C9 66 89 8C 04 60 01 00 00 }
      $obfuscation2 = { 48 6B C0 02 C6 44 04 20 BA B8 01 00 00 00 48 6B C0 03 C6 44 04 20 9A B8 01 00 00 00 48 6B C0 04 C6 44 04 20 8B B8 01 00 00 00 48 6B C0 05 C6 44 04 20 8A B8 01 00 00 00 48 6B C0 06 C6 44 04 20 9C B8 01 00 00 00 }
      $obfuscation3 = { 48 6B C0 00 C6 44 04 20 A8 B8 01 00 00 00 48 6B C0 01 C6 44 04 20 9A B8 01 00 00 00 48 6B C0 02 C6 44 04 20 93 B8 01 00 00 00 48 6B C0 03 C6 44 04 20 96 B8 01 00 00 00 48 6B C0 04 C6 44 04 20 B9 B8 01 00 00 00 48 6B C0 05 C6 44 04 20 9A B8 01 00 00 00 48 6B C0 06 C6 44 04 20 8B B8 01 00 00 00 48 6B C0 07 C6 44 04 20 9E B8 01 00 00 00 48 6B C0 08 C6 44 04 20 9A B8 01 00 00 00 48 6B C0 09 C6 44 04 20 8D B8 01 00 00 00 48 6B C0 0A C6 44 04 20 BC B8 01 00 00 00 }
   condition:
      uint16(0) == 0x5A4D 
      and $obfuscation1 and $obfuscation2 and $obfuscation3
}
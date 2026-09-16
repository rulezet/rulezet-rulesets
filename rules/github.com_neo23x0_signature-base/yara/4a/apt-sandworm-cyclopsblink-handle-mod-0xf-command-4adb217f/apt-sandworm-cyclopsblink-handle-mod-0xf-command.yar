rule APT_Sandworm_CyclopsBlink_handle_mod_0xf_command {
   meta:
      author = "NCSC"
      description = "Detects the code bytes used to check module ID 0xf control flags and a format string used for file content upload"
      hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
      hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"
      reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
      date = "2022-02-23"
      id = "36646b7a-389d-5fd9-88a1-e43e7224763a"
   strings:
            $ = {54 00 06 3E 54 00 07 FE 54 00 06 3E 2F 80 00 00}
            $ = {54 00 06 3E 54 00 07 BC 2F 80 00 00}
            $ = {54 00 06 3E 54 00 07 7A 2F 80 00 00}
            $ = {54 00 06 3E 54 00 06 F6 2F 80 00 00}
            $ = "file:%s\n" fullword
   condition:
      (uint32(0) == 0x464c457f) and (all of them)
}
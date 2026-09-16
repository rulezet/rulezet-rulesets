rule APT_Sandworm_CyclopsBlink_default_config_values {
   meta:
      author = "NCSC"
      description = "Detects the code bytes used to set default Cyclops Blink configuration values"
      hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
      hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"
      reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
      date = "2022-02-23"
      id = "04067609-1173-51f2-907f-2a236aae6c7c"
   strings:
            $ = {38 00 00 19 90 09 01 A4}
            $ = {3C 00 00 01 60 00 80 00 90 09 01 A8}
            $ = {38 00 40 00 90 09 01 AC}
            $ = {38 00 01 0B 90 09 01 B0}
            $ = {38 00 27 11 90 09 01 C0}
   condition:
      (uint32(0) == 0x464c457f) and (3 of them)
}
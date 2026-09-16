rule APT_Sandworm_CyclopsBlink_config_identifiers {
   meta:
      author = "NCSC"
      description = "Detects the initial characters used to identify Cyclops Blink configuration data"
      hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
      hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"
      reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
      date = "2022-02-23"
      id = "db5b3a4a-82c2-500a-88f6-340b3392eac8"
   strings:
                        $ = {3C 00 3C 6B 60 00 3A 20 90 09 00 00}
            $ = {3C 00 3C 63 60 00 3A 20 90 09 00 00}
            $ = {3C 00 3C 73 60 00 3A 20 90 09 00 00}
   condition:
      (uint32(0) == 0x464c457f) and (all of them)
}
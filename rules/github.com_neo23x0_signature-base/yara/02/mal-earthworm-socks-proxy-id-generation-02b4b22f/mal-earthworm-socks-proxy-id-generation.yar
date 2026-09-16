rule MAL_EarthWorm_Socks_Proxy_ID_Generation {
   meta:
      description = "Detects EarthWorm - a reverse socks proxy used by the threat group that deployed Pygmy Goat malware on Sophos XG firewall devices. The detection is based on the pool num generation x86 assembly."
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/pygmy-goat/ncsc-mar-pygmy-goat.pdf"
      author = "NCSC"
      date = "2024-10-22"
      score = 75
      hash1 = "71f70d61af00542b2e9ad64abd2dda7e437536ff"
      id = "242777e4-3abb-50d8-8c45-746cc4a8b1f8"
   strings:
      $chartoi = {
         8b 45 ??          c1 e0 07          89 c1          8b 55 ??          8b 45 ??          01 d0          0f b6 00          0f be c0          01 c8          89 45 ??          83 6d ?? 01       }
   condition:
      uint32(0) == 0x464c457f and all of them
}
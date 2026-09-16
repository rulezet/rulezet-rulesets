rule APT_APT29_sorefang_encryption_key_schedule { 
   meta:
      description = "Rule to detect SoreFang based on the key schedule used for encryption"
      author = "NCSC"
      reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
      hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
      id = "8d89edc1-a9fc-5155-9dc2-8d7f952f90d1"
   strings:
      $ = { C7 05 ?? ?? ?? ?? 63 51 E1 B7 B8 ?? ?? ?? ?? 8B 48 
            FC 81 E9 47 86 C8 61 89 08 83 C0 04 3D ?? ?? ?? ?? 
            7E EB 33 D2 33 C9 B8 2C 00 00 00 89 55 D4 33 F6 89 
            4D D8 33 DB 3B F8 0F 4F C7 8D 04 40 89 45 D0 83 F8 
            01 7C 4F 0F 1F 80 00 00 00 00 }
   condition:
      (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and any of them 
}
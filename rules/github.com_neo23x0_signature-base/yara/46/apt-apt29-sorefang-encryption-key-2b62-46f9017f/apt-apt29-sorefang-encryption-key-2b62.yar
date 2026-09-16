rule APT_APT29_sorefang_encryption_key_2b62 {
  meta:
      description = "Rule to detect SoreFang based on hardcoded encryption key"
      author = "NCSC"
      reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
      hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
      id = "9a7abad7-1cfa-52c8-9416-47cb80486714"
   strings:
      $ = "2b6233eb3e872ff78988f4a8f3f6a3ba"
   condition:
      ( uint16(0) == 0x5A4D and uint16(uint32(0x3c) ) == 0x4550) 
      and any of them 
}
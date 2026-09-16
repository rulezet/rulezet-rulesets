rule APT_APT29_sorefang_remove_chars_comma_space_dot { 
   meta:
      description = "Rule to detect SoreFang based on function that removes commas, spaces and dots"
      author = "NCSC"
      reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
      hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
      id = "c15779b0-6a5e-5345-94ad-95615b567f1f"
   strings:
      $ = {8A 18 80 FB 2C 74 03 88 19 41 42 40 3B D6 75 F0 8B 5D 08} 
      $ = {8A 18 80 FB 2E 74 03 88 19 41 42 40 3B D6 75 F0 8B 5D 08} 
      $ = {8A 18 80 FB 20 74 03 88 19 41 42 40 3B D6 75 F0 8B 5D 08}
   condition:
      (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and all of them 
}
rule MAL_WAR_Ivanti_EPMM_MobileIron_Mi_War_Aug23_RID365A : CVE_2023_35078 DEMO FILE MAL {
   meta:
      description = "Detects WAR file found in the Ivanti EPMM / MobileIron Core compromises exploiting CVE-2023-35078"
      author = "Florian Roth"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-213a"
      date = "2023-08-01 16:52:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6255c75e2e52d779da39367e7a7d4b8d1b3c9c61321361952dcc05819251a127"
      tags = "CVE_2023_35078, DEMO, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "logsPaths.txt" ascii fullword
      $s2 = "keywords.txtFirefox" ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and filesize < 20KB and all of them
}
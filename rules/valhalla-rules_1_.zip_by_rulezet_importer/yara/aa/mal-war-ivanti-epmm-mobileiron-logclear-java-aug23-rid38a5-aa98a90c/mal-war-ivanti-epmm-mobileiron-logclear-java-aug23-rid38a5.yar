rule MAL_WAR_Ivanti_EPMM_MobileIron_LogClear_JAVA_Aug23_RID38A5 : CVE_2023_35078 DEMO MAL {
   meta:
      description = "Detects LogClear.class found in the Ivanti EPMM / MobileIron Core compromises exploiting CVE-2023-35078"
      author = "Florian Roth"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-213a"
      date = "2023-08-01 18:30:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "deb381c25d7a511b9eb936129eeba2c0341cff7f4bd2168b05e40ab2ee89225e"
      tags = "CVE_2023_35078, DEMO, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "logsPaths.txt" ascii fullword
      $s2 = "log file: %s, not read" ascii fullword
      $s3 = "/tmp/.time.tmp" ascii fullword
      $s4 = "readKeywords" ascii fullword
      $s5 = "\"----------------  ----------------" ascii fullword
   condition: 
      uint16 ( 0 ) == 0xfeca and filesize < 20KB and 4 of them or all of them
}
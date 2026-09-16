rule MAL_DLL_Stealer_Nov23_RID2E4C : CVE_2023_4966 DEMO EXE FILE MAL RANSOM {
   meta:
      description = "Detects a DLL that steals authentication credentials - was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
      author = "X__Junior"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
      date = "2023-11-23 11:08:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "17a27b1759f10d1f6f1f51a11c0efea550e2075c2c394259af4d3f855bbcc994"
      tags = "CVE_2023_4966, DEMO, EXE, FILE, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { C7 45 ?? 4D 69 6E 69 C7 45 ?? 44 75 6D 70 C7 45 ?? 57 72 69 74 C7 45 ?? 65 44 75 6D C7 45 ?? 70 00 27 00 C7 45 ?? 44 00 62 00 C7 45 ?? 67 00 68 00 C7 45 ?? 65 00 6C 00 C7 45 ?? 70 00 2E 00 C7 45 ?? 64 00 6C 00 C7 45 ?? 6C 00 00 00 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and all of them
}
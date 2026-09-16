rule MAL_Trojan_DLL_Nov23_RID2DEA : CVE_2023_4966 DEMO EXE FILE MAL RANSOM {
   meta:
      description = "Detects a trojan DLL that installs other components - was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
      author = "X__Junior"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
      date = "2023-11-23 10:52:11"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e557e1440e394537cca71ed3d61372106c3c70eb6ef9f07521768f23a0974068"
      tags = "CVE_2023_4966, DEMO, EXE, FILE, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { C7 84 24 ?? ?? ?? ?? 52 70 63 53 C7 84 24 ?? ?? ?? ?? 74 72 69 6E C7 84 24 ?? ?? ?? ?? 67 42 69 6E C7 84 24 ?? ?? ?? ?? 64 69 6E 67 C7 84 24 ?? ?? ?? ?? 43 6F 6D 70 C7 84 24 ?? ?? ?? ?? 6F 73 65 41 C7 84 24 ?? ?? ?? ?? 00 40 01 01 } 
      $op2 = { C7 84 24 ?? ?? ?? ?? 6C 73 61 73 C7 84 24 ?? ?? ?? ?? 73 70 69 72 66 C7 84 24 ?? ?? 00 00 70 63 } 
      $op3 = { C7 84 24 ?? ?? ?? ?? 4E 64 72 43 C7 84 24 ?? ?? ?? ?? 6C 69 65 6E C7 84 24 ?? ?? ?? ?? 74 43 61 6C C7 84 24 ?? ?? ?? ?? 6C 33 00 8D } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and all of them
}
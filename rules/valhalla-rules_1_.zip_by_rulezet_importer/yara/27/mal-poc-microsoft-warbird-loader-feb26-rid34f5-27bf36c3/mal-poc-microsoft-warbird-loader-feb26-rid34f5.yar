rule MAL_POC_Microsoft_Warbird_Loader_Feb26_RID34F5 : DEMO EXE FILE MAL Warbird_Loader {
   meta:
      description = "Detects a POC to turn Microsoft Warbird into a shellcode loader"
      author = "X__Junior"
      reference = "https://cirosec.de/en/news/abusing-microsoft-warbird-for-shellcode-execution/"
      date = "2026-02-03 15:52:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL, Warbird_Loader"
      minimum_yara = "3.5.0"
      
   strings:
      $op = { fe af fe ca ef be ad de } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and $op
}
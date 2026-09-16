rule MAL_POC_Microsoft_Warbird_Loader_Feb26 {
   meta:
      description = "Detects a POC to turn Microsoft Warbird into a shellcode loader"
      author = "X__Junior"
      date = "2026-02-03"
      reference = "https://cirosec.de/en/news/abusing-microsoft-warbird-for-shellcode-execution/"
      hash = "29d0467ee452752286318f350ceb28a2b04ee4c6de550ba0edc34ae0fa7cbb03"
      score = 75
      id = "a07f6d10-c463-56a6-a667-82b1c00760af"
   strings:
      $op = { fe af fe ca ef be ad de }
   condition:
      uint16(0) == 0x5a4d and $op
}
rule SUSP_OBFUSC_SH_Indicators_Mar24_1 {
   meta:
      description = "Detects characteristics found in obfuscated script (used in the backdoored XZ package, but could match on others, too)"
      author = "Florian Roth"
      reference = "https://www.openwall.com/lists/oss-security/2024/03/29/4/1"
      date = "2024-04-06"
      score = 60
      id = "f9fcc326-75d6-5a5a-a8b5-7de15a11448e"
   strings:
      $s1 = "eval $"
   condition:
      uint8(1) == 0x3d       and $s1 in (filesize-20..filesize) }
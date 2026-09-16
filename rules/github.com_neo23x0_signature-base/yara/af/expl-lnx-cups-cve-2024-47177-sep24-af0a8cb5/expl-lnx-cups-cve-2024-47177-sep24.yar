rule EXPL_LNX_CUPS_CVE_2024_47177_Sep24 {
   meta:
      description = "Detects exploit code for CUPS CVE-2024-47177"
      author = "Florian Roth"
      reference = "https://github.com/OpenPrinting/cups-browsed/security/advisories/GHSA-rj88-6mr5-rcw8"
      date = "2024-09-27"
      score = 75
      id = "a7b986ad-e943-5350-a6e0-34c40f07874c"
   strings:
      $s1 = "FoomaticRIPCommandLine: " ascii
      $s2 = "cupsFilter2 : " ascii
   condition:
      filesize < 400KB and all of them
}
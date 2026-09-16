rule MAL_APT_NK_Andariel_TigerRAT_Crowdsourced_Rule {
   meta:
      author = "CISA.gov (modified by Florian Roth, Nextron Systems)"
      description = "Detects the Tiger RAT variant used by Andariel"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      modified = "2024-07-26"
      score = 75
      id = "6be65222-7d3c-5ff5-a9c7-d91dcf1deaa6"
   strings:
      $m1 = ".?AVModuleKeyLogger@@" fullword ascii
      $m2 = ".?AVModulePortForwarder@@" fullword ascii
      $m3 = ".?AVModuleScreenCapture@@" fullword ascii
      $m4 = ".?AVModuleShell@@" fullword ascii

      $s1 = "\\x9891-009942-xnopcopie.dat" fullword wide
      $s2 = "(%02d : %02d-%02d %02d:%02d:%02d)--- %s[Clipboard]" fullword ascii
      $s3 = "[%02d : %02d-%02d %02d:%02d:%02d]--- %s[Title]" fullword ascii
      $s4 = "del \"%s\"%s \"%s\" goto " ascii
         condition:
      uint16(0) == 0x5a4d and (
         all of ($s*) or (
            all of ($m*) and 1 of ($s*)
         ) 
         or (
            2 of ($m*) and 2 of ($s*)
         )
      )
}
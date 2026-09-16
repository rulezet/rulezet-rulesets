rule MAL_Cisco_LINE_VIPER_Shellcode_Initial_Execution {
   meta:
      author = "NCSC (modifier by Florian Roth)"
      description = "Detects LINE VIPER Cisco ASA malware code as part of shellcode initial execution."
      date = "2025-09-25"
      modified = "2025-09-27"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
      score = 85
      license = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
   strings:
      $xc1 = {
         48 8D B7 80 00 00 00 BA 00 20 00 00 [19] 48 C7 C6 00
         90 00 00 BA 07 00 00 00
      }
                        $xe1 = { 53 49 32 33 67 41 41 41 41 4c 6f 41 49 41 41 41 [26] 6a 48 78 67 43 51 41 41 43 36 42 77 41 41 41 }
      $xe2 = { 69 4e 74 34 41 41 41 41 43 36 41 43 41 41 41 [26] 49 78 38 59 41 6b 41 41 41 75 67 63 41 41 41 }
      $xe3 = { 49 6a 62 65 41 41 41 41 41 75 67 41 67 41 41 [26] 53 4d 66 47 41 4a 41 41 41 4c 6f 48 41 41 41 41 }
   condition:
      1 of them
}
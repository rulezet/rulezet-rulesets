rule MAL_Cisco_LINE_VIPER_ICMP_Tasking_Shellcode_Payloads {
   meta:
      author = "NCSC"
      description = "Detects LINE VIPER Cisco ASA malware code as part of ICMP tasking shellcode payloads."
      date = "2025-09-25"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
      score = 85
      license = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
   strings:
      $ = {
         55 53 41 54 41 55 41 56 41 57 48 89 E5 48 83 EC 60 48
         31 C0 B9 07 00 00 00 48 8D 7D A8 F3 48 AB BF 01 00 00
         00 BE 30 00 00 00
      }
      $ = {
         49 89 C7 48 C7 C2 38 DF FF FF 64 48 8B 0A 48 8B 99 00
         01 00 00 48 89 81 00 01 00 00
      }
      $ = {
         49 8B 47 10 48 8D 55 B0 BE 01 20 01 00 4C 89 FF FF 90
         90 00 00 00 48 8B 7D B0 48 85 FF 0F 84 3C 00 00 00
      }
      $ = {
         49 8B 47 10 BE 08 20 01 00 4C 89 FF 48 8D 55 A8 FF 90
         90 00 00 00 48 8B 7D B0 49 89 7E 20 48 8B 7D A8 49 89
         7E 28
      }
   condition:
      3 of them
}
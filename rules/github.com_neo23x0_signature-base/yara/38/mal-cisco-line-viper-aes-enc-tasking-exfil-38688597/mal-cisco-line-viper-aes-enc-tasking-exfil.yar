rule MAL_Cisco_LINE_VIPER_AES_Enc_Tasking_Exfil {
   meta:
      author = "NCSC"
      description = "Detects LINE VIPER Cisco ASA malware code as part of AES encrypted tasking and exfiltration."
      date = "2025-09-25"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
      score = 85
      license = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
   strings:
      $ = {
         48 31 C0 48 89 45 D8 49 89 FC 49 89 F5 49 89 D6 48 8B
         47 08 48 89 45 B8 48 8D 40 40 48 89 45 E0 48 8D 70 E0 48 89 75 B0
         48 8D 78 F0 48 89 7D E8 BA 10 00 00 00
      }
      $ = {
         48 85 C0 0F 84 EA 00 00 00 48 89 45 A8 4C 89 EF 48 89
         C6 4C 89 F2 48 8B 4D A0 4C 8B 45 B0 4D 31 C9
      }
      $ = {
         48 85 C0 0F 84 82 00 00 00 49 89 C7 48 8B 7D E0 BE 00
         01 00 00 48 8B 55 A0
      }
      $ = {
         48 8B 7D D0 49 83 C7 10 49 C1 EF 04 49 C1 E7 04 4C 89
         FE 48 8D 55 D8
      }
   condition:
      3 of them
}
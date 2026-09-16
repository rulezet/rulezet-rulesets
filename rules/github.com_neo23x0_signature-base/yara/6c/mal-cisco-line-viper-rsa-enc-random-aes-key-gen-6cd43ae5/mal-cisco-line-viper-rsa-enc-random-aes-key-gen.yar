rule MAL_Cisco_LINE_VIPER_RSA_Enc_Random_AES_Key_Gen {
   meta:
      author = "NCSC"
      description = "Detects LINE VIPER Cisco ASA malware code as part of RSA encrypted random AES key generation."
      date = "2025-09-25"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
      score = 85
      license = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
   strings:
      $xc1 = {
         48 31 C0 49 89 06 49 89 46 08 49 83 C6 10 49 83 ED 10
         4D 85 ED 75 D8 BF 30 00 00 00
      }
      $xc2 = {
         0F 85 57 01 00 00 49 8B 44 24 08 48 83 F8 2F 7C 33 41
         BD F0 02 00 00 4D 8D 74 24 10 49 8B 3E
      }
      $xc3 = {
         85 C0 0F 8E EE 00 00 00 41 BD F0 02 00 00 4D 8D 7C 24
         10 49 8B 3F 48 85 FF 74 0D 49 83 C7 10 49 83 ED 10 4D 85 ED 75 EB
         4D 89 37 BF 70 00 00 00
      }
      $xc4 = {
         48 85 C0 0F 84 3F 00 00 00 48 89 45 B0 BF 80 00 00 00
         4C 89 EE 48 89 C2 48 8B 4D A8 41 B8 01 00 00 00
      }
   condition:
      1 of them
}
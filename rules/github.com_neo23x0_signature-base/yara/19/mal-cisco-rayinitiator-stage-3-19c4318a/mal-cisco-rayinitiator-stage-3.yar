rule MAL_Cisco_RayInitiator_Stage_3 {
   meta:
      author = "NCSC"
      description = "Detects RayInitiator GRUB bootkit stage 3 install phase code that searches for the 'client-cert-fail' string."
      date = "2025-09-25"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
      score = 85
      license = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
   strings:
      $xc1 = {
         48 81 EE 00 00 00 08 48 B8 63 6C 69 65 6E 74 2D 63 49
         B8 65 72 74 2D 66 61 69 6C 48 FF C6 48 39 D6 0F 87 D2
         00 00 00 48 8B 3E 48 39 C7
      }
   condition:
      $xc1
}
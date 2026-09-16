rule MAL_Cisco_RayInitiator_Stage_3_LINE_VIPER_ShellCode {
   meta:
      author = "NCSC"
      description = "Detects RayInitiator GRUB bootkit stage 3 deploy phase code that copies LINE VIPER shellcode stub and marks executable."
      date = "2025-09-25"
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
      score = 85
   strings:
      $xc1 = {
         48 89 FA 48 83 C7 40 4C 89 CE B9 D0 01 00 00 F3 A4 48
         89 D7 48 83 C7 40 48 89 3A 48 C1 EF 0C 48 C1 E7 0C BA
         07 00 00 00 48 C7 C6 00 20 00 00
      }
   condition:
      $xc1
}
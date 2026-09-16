rule LOG_EXPL_ADSelfService_CVE_2021_40539_WebLog_Sep21_1_RID37A8 : CVE_2021_40539 DEMO EXPLOIT LOG {
   meta:
      description = "Detects suspicious log lines produeced during the exploitation of ADSelfService vulnerability CVE-2021-40539"
      author = "Florian Roth"
      reference = "https://us-cert.cisa.gov/ncas/alerts/aa21-259a"
      date = "2021-09-20 17:47:51"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2021_40539, DEMO, EXPLOIT, LOG"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "/ServletApi/../RestApi/LogonCustomization" ascii wide
      $x2 = "/ServletApi/../RestAPI/Connection" ascii wide
   condition: 
      filesize < 50MB and 1 of them
}
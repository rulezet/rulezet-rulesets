rule LOG_EXPL_Ivanti_EPMM_MobileIron_Core_CVE_2023_35078_Jul23_1_RID3A62 : CVE_2023_35078 DEMO EXPLOIT LOG {
   meta:
      description = "Detects the successful exploitation of Ivanti Endpoint Manager Mobile (EPMM) / MobileIron Core CVE-2023-35078"
      author = "Florian Roth"
      reference = "Ivanti Endpoint Manager Mobile (EPMM) CVE-2023-35078 - Analysis Guidance"
      date = "2023-07-25 19:44:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2023_35078, DEMO, EXPLOIT, LOG"
      minimum_yara = "3.5.0"
      
   strings:
      $xr1 = /\/mifs\/aad\/api\/v2\/[^\n]{1,300} 200 [1-9][0-9]{0,60} / 
   condition: 
      $xr1
}
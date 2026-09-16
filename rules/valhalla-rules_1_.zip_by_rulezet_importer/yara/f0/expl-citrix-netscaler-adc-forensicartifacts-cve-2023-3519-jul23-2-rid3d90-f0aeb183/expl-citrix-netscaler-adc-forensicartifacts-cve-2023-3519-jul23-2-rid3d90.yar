rule EXPL_Citrix_Netscaler_ADC_ForensicArtifacts_CVE_2023_3519_Jul23_2_RID3D90 : CVE_2023_3519 DEMO EXPLOIT {
   meta:
      description = "Detects forensic artifacts found after an exploitation of Citrix NetScaler ADC CVE-2023-3519"
      author = "Florian Roth"
      reference = "https://www.cisa.gov/sites/default/files/2023-07/aa23-201a_csa_threat_actors_exploiting_citrix-cve-2023-3519_to_implant_webshells.pdf"
      date = "2023-07-21 21:59:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2023_3519, DEMO, EXPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "tar -czvf - /var/tmp/all.txt" ascii fullword
      $s2 = "-out /var/tmp/test.tar.gz" ascii
      $s3 = "/test.tar.gz /netscaler/" 
   condition: 
      filesize < 10MB and 1 of them
}
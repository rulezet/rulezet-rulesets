rule CVE_2017_8759_SOAP_Excel_RID2E36 : CVE_2017_8759 DEMO EXPLOIT OFFICE T1203 T1566_001 {
   meta:
      description = "Detects malicious files related to CVE-2017-8759"
      author = "Florian Roth"
      reference = "https://twitter.com/buffaloverflow/status/908455053345869825"
      date = "2017-09-15 11:04:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2017_8759, DEMO, EXPLOIT, OFFICE, T1203, T1566_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "|'soap:wsdl=" ascii wide nocase
   condition: 
      ( filesize < 300KB and 1 of them )
}
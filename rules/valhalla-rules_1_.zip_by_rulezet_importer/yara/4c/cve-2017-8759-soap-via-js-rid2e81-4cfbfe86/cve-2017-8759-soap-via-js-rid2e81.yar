rule CVE_2017_8759_SOAP_via_JS_RID2E81 : CVE_2017_8759 DEMO EXPLOIT T1059_007 {
   meta:
      description = "Detects SOAP WDSL Download via JavaScript"
      author = "Florian Roth"
      reference = "https://twitter.com/buffaloverflow/status/907728364278087680"
      date = "2017-09-14 11:17:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2017_8759, DEMO, EXPLOIT, T1059_007"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "GetObject(\"soap:wsdl=https://" ascii wide nocase
      $s2 = "GetObject(\"soap:wsdl=http://" ascii wide nocase
   condition: 
      ( filesize < 3KB and 1 of them )
}
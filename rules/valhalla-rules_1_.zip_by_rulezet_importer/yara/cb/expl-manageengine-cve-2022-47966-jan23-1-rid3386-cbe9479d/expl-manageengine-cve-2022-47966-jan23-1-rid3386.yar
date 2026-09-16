rule EXPL_ManageEngine_CVE_2022_47966_Jan23_1_RID3386 : CVE_2022_47966 DEMO EXPLOIT {
   meta:
      description = "Detects indicators of exploitation of ManageEngine vulnerability as described by Horizon3"
      author = "Florian Roth"
      reference = "https://www.horizon3.ai/manageengine-cve-2022-47966-iocs/"
      date = "2023-01-13 14:51:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2022_47966, DEMO, EXPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $ = "]: com.adventnet.authentication.saml.SamlException: Signature validation failed. SAML Response rejected|" 
   condition: 
      1 of them
}
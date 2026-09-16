import "pe"
rule SUSP_TH_APT_UNC4736_TradingTech_Cert_Apr23_1_RID35C4 : APT DEMO G1049 SUSP {
   meta:
      description = "Threat hunting rule that detects samples signed with the compromised Trading Technologies certificate after May 2022"
      author = "Florian Roth"
      reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
      date = "2023-04-20 16:27:11"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, G1049, SUSP"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = { 00 85 38 A6 C5 01 8F 50 FC } 
      $s2 = "Go Daddy Secure Certificate Authority - G2" 
      $s3 = "Trading Technologies International, Inc" 
   condition: 
      pe.timestamp > 1651363200 and all of them
}
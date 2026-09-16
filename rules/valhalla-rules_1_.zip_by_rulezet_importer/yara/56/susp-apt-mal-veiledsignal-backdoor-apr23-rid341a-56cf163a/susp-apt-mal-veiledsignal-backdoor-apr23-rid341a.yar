rule SUSP_APT_MAL_VEILEDSIGNAL_Backdoor_Apr23_RID341A : APT DEMO MAL SUSP {
   meta:
      description = "Detects marker found in VEILEDSIGNAL backdoor"
      author = "X__Junior"
      reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
      date = "2023-04-20 15:16:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-04-21"
      hash1 = "aa318070ad1bf90ed459ac34dc5254acc178baff3202d2ea7f49aaf5a055dd43"
      tags = "APT, DEMO, MAL, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $opb1 = { 81 BD ?? ?? ?? ?? 5E DA F3 76 } 
      $opb2 = { C7 85 ?? ?? ?? ?? 74 F2 39 DA 66 C7 85 ?? ?? ?? ?? E5 CF } 
      $opb3 = { C7 85 ?? ?? ?? ?? 74 F2 39 DA B9 00 04 00 00 66 C7 85 ?? ?? ?? ?? E5 CF } 
   condition: 
      2 of them
}
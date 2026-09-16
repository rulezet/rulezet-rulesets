rule APT_MAL_VEILEDSIGNAL_Backdoor_Apr23_4_RID3303 : APT DEMO MAL {
   meta:
      description = "Detects malicious VEILEDSIGNAL backdoor"
      author = "X__Junior"
      reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/xtrader-3cx-supply-chain"
      date = "2023-04-29 14:29:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 48 8D 15 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 85 C0 } 
      $op2 = { 48 8B C8 48 8D 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 45 33 C0 4C 8D 4D ?? B2 01 41 8D 48 ?? FF D0 } 
      $op3 = { 33 FF C7 44 24 ?? 38 02 00 00 33 D2 8D 4F ?? FF 15 ?? ?? ?? ?? 48 8B D8 48 83 F8 FF 74 ?? 48 8D 54 24 ?? 48 8B C8 FF 15 } 
      $op4 = { 4C 8D 05 ?? ?? ?? ?? 48 89 4C 24 ?? 4C 8B C8 33 D2 89 4C 24 ?? FF 15 } 
   condition: 
      all of them
}
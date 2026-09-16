rule APT_MAL_VEILEDSIGNAL_Backdoor_Apr23_RID3270 : APT DEMO EXE FILE MAL {
   meta:
      description = "Detects malicious VEILEDSIGNAL backdoor"
      author = "X__Junior"
      reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
      date = "2023-04-20 14:05:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "aa318070ad1bf90ed459ac34dc5254acc178baff3202d2ea7f49aaf5a055dd43"
      tags = "APT, DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { B8 AB AA AA AA F7 E1 8B C1 C1 EA 02 8D 14 52 03 D2 2B C2 8A 84 05 ?? ?? ?? ?? 30 84 0D ?? ?? ?? ?? } 
      $op2 = { 50 66 0F 13 85 ?? ?? ?? ?? 66 0F 13 85 ?? ?? ?? ?? 66 0F 13 85 ?? ?? ?? ?? 66 0F 13 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 3C 00 00 00 C7 85 ?? ?? ?? ?? 40 00 00 00 C7 85 ?? ?? ?? ?? 05 00 00 00 FF 15 } 
      $op3 = { 6A 00 8D 85 ?? ?? ?? ?? 50 6A 04 8D 85 ?? ?? ?? ?? 50 57 FF 15 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and all of them
}
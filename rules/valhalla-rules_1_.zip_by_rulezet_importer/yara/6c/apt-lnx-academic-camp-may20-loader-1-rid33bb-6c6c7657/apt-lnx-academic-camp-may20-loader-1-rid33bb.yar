rule APT_LNX_Academic_Camp_May20_Loader_1_RID33BB : APT DEMO FILE LINUX {
   meta:
      description = "Detects malware used in attack on academic data centers"
      author = "Florian Roth"
      reference = "https://csirt.egi.eu/academic-data-centers-abused-for-crypto-currency-mining/"
      date = "2020-05-16 15:00:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0efdd382872f0ff0866e5f68f0c66c01fcf4f9836a78ddaa5bbb349f20353897"
      tags = "APT, DEMO, FILE, LINUX"
      minimum_yara = "3.5.0"
      
   strings:
      $sc1 = { C6 45 F1 00 C6 45 F2 0A C6 45 F3 0A C6 45 F4 4A C6 45 F5 04 C6 45 F6 06 C6 45 F7 1B C6 45 F8 01 } 
      $sc2 = { 01 48 39 EB 75 EA 48 83 C4 08 5B 5D 41 5C 41 5D } 
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 10KB and all of them
}
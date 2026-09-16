rule BronzeButler_DGet_1_RID2E42 : APT CHINA DEMO EXE FILE G0060 {
   meta:
      description = "Detects malware / hacktool sample from Bronze Butler incident"
      author = "Florian Roth"
      reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
      date = "2017-10-14 11:06:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "bd81521445639aaa5e3bcb5ece94f73feda3a91880a34a01f92639f8640251d6"
      tags = "APT, CHINA, DEMO, EXE, FILE, G0060"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "DGet Tool Made by XZ" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 10KB and 1 of them )
}
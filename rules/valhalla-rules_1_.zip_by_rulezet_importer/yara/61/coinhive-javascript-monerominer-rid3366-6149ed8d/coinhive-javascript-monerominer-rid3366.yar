rule CoinHive_Javascript_MoneroMiner_RID3366 : DEMO HIGHVOL SUSP {
   meta:
      description = "Detects CoinHive - JavaScript Crypto Miner"
      author = "Florian Roth"
      reference = "https://coinhive.com/documentation/miner"
      date = "2018-01-04 14:46:11"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HIGHVOL, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "CoinHive.CONFIG.REQUIRES_AUTH" fullword ascii
   condition: 
      filesize < 65KB and 1 of them
}
rule CoinHive_Javascript_MoneroMiner : HIGHVOL {
   meta:
      description = "Detects CoinHive - JavaScript Crypto Miner"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 50
      reference = "https://coinhive.com/documentation/miner"
      date = "2018-01-04"
      id = "4f40c342-fcdc-5c73-a3cf-7b2ed438eaaf"
   strings:
      $s2 = "CoinHive.CONFIG.REQUIRES_AUTH" fullword ascii
   condition:
      filesize < 65KB and 1 of them
}
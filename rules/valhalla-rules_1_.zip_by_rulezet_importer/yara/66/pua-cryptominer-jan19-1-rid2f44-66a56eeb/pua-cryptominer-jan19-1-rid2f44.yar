rule PUA_CryptoMiner_Jan19_1_RID2F44 : DEMO MAL {
   meta:
      description = "Detects Crypto Miner strings"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-01-31 11:49:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ede858683267c61e710e367993f5e589fcb4b4b57b09d023a67ea63084c54a05"
      tags = "DEMO, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Stratum notify: invalid Merkle branch" fullword ascii
      $s2 = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
      $s3 = "User-Agent: cpuminer/" ascii
      $s4 = "hash > target (false positive)" fullword ascii
      $s5 = "thread %d: %lu hashes, %s khash/s" fullword ascii
   condition: 
      filesize < 1000KB and 1 of them
}
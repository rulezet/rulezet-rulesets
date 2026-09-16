rule SUSP_LNX_SH_CryptoMiner_Indicators_Dec20_1_RID364E : DEMO LINUX SCRIPT SUSP {
   meta:
      description = "Detects helper script used in a crypto miner campaign"
      author = "Florian Roth"
      reference = "https://www.intezer.com/blog/research/new-golang-worm-drops-xmrig-miner-on-servers/"
      date = "2020-12-31 16:50:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3298dbd985c341d57e3219e80839ec5028585d0b0a737c994363443f4439d7a5"
      tags = "DEMO, LINUX, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "miner running" fullword ascii
      $x2 = "miner runing" fullword ascii
      $x3 = " --donate-level 1 " 
      $x4 = " -o pool.minexmr.com:5555 " ascii
   condition: 
      filesize < 20KB and 1 of them
}
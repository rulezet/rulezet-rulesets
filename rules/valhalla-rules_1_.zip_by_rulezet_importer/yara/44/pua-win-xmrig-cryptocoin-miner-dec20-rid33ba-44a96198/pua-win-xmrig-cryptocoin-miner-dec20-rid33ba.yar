rule PUA_WIN_XMRIG_CryptoCoin_Miner_Dec20_RID33BA : DEMO EXE MAL xmrig {
   meta:
      description = "Detects XMRIG crypto coin miners"
      author = "Florian Roth"
      reference = "https://www.intezer.com/blog/research/new-golang-worm-drops-xmrig-miner-on-servers/"
      date = "2020-12-31 15:00:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b6154d25b3aa3098f2cee790f5de5a727fc3549865a7aa2196579fe39a86de09"
      tags = "DEMO, EXE, MAL, xmrig"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "xmrig.exe" fullword wide
      $x2 = "xmrig.com" fullword wide
      $x3 = "* for x86, CRYPTOGAMS" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 6000KB and 2 of them or all of them
}
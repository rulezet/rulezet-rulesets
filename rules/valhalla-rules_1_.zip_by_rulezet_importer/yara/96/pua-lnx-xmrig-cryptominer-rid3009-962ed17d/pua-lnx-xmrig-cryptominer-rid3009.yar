rule PUA_LNX_XMRIG_CryptoMiner_RID3009 : DEMO FILE LINUX MAL xmrig {
   meta:
      description = "Detects XMRIG CryptoMiner software"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-06-28 12:22:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      hash1 = "10a72f9882fc0ca141e39277222a8d33aab7f7a4b524c109506a407cd10d738c"
      tags = "DEMO, FILE, LINUX, MAL, xmrig"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "number of hash blocks to process at a time (don't set or 0 enables automatic selection o" fullword ascii
      $s2 = "'h' hashrate, 'p' pause, 'r' resume, 'q' shutdown" fullword ascii
      $s3 = "* THREADS:      %d, %s, aes=%d, hf=%zu, %sdonate=%d%%" fullword ascii
      $s4 = ".nicehash.com" ascii
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 8000KB and ( 1 of ( $x* ) or 2 of them )
}
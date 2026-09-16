rule PUA_LNX_XMRIG_CryptoMiner {
   meta:
      description = "Detects XMRIG CryptoMiner software"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-06-28"
      modified = "2023-01-06"
      hash1 = "10a72f9882fc0ca141e39277222a8d33aab7f7a4b524c109506a407cd10d738c"
      id = "bbdeff2e-68cc-5bbe-b843-3cba9c8c7ea8"
   strings:
      $x1 = "number of hash blocks to process at a time (don't set or 0 enables automatic selection o" fullword ascii
      $s2 = "'h' hashrate, 'p' pause, 'r' resume, 'q' shutdown" fullword ascii
      $s3 = "* THREADS:      %d, %s, aes=%d, hf=%zu, %sdonate=%d%%" fullword ascii
      $s4 = ".nicehash.com" ascii
   condition:
      uint16(0) == 0x457f and filesize < 8000KB and ( 1 of ($x*) or 2 of them )
}
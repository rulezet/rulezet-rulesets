rule EXPL_HKTL_LNX_DirtyFragLPE_May26 {
   meta:
      description = "Detects dirtyfrag, a local privilege escalation exploit for Linux."
      author = "Pezier Pierre-Henri (Nextron Systems)"
      date = "2026-05-07"
      score = 80
      hash = "c35594d42f7a5d5d2895164147ee1bc62bb8e294c8468093b7d6fcaab0b174c8"
      reference = "https://github.com/V4bel/dirtyfrag/tree/master"
      id = "7548b4c6-6b0f-5c05-acab-26dceac109ac"
   strings:
            $x1 = "gained CAP_NET_RAW within netn" ascii
      $x2 = "DIRTYFRAG_VERBOSE" ascii

      $s1 = { 15 7C 4A 7F B9 79 37 9E }        $s2 = "/proc/self/setgroups" ascii fullword
      $s3 = "pcbc(fcrypt)" ascii fullword
      $s4 = { 17 bb c7 f3 3f 36 ba 71 8e 97 65 60 69 b6 f6 e6 }
   condition:
      filesize < 100KB
      and uint32be(0) == 0x7f454c46
      and (
         1 of ($x*)
         or 3 of ($s*)
      )
}
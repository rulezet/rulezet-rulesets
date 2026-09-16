rule TTP_XOR_QUAD_CurrentVersionRun_0a45 {
  strings:
    $key_0a45 = { 59 2a [2] 7d 24 [2] 56 08 [2] 78 2a [2] 6c 31 [2] 63 2b [2] 7d 36 [2] 7f 37 [2] 64 31 [2] 78 36 [2] 64 19 }

  condition:
    any of them
}
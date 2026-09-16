rule TTP_XOR_QUAD_CurrentVersionRun_4645 {
  strings:
    $key_4645 = { 15 2a [2] 31 24 [2] 1a 08 [2] 34 2a [2] 20 31 [2] 2f 2b [2] 31 36 [2] 33 37 [2] 28 31 [2] 34 36 [2] 28 19 }

  condition:
    any of them
}
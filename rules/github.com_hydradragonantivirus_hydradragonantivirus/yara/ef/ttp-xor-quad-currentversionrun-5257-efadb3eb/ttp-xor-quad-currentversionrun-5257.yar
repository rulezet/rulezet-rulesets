rule TTP_XOR_QUAD_CurrentVersionRun_5257 {
  strings:
    $key_5257 = { 01 38 [2] 25 36 [2] 0e 1a [2] 20 38 [2] 34 23 [2] 3b 39 [2] 25 24 [2] 27 25 [2] 3c 23 [2] 20 24 [2] 3c 0b }

  condition:
    any of them
}
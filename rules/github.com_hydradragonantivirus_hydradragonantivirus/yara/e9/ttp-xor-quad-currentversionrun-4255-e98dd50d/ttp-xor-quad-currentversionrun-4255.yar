rule TTP_XOR_QUAD_CurrentVersionRun_4255 {
  strings:
    $key_4255 = { 11 3a [2] 35 34 [2] 1e 18 [2] 30 3a [2] 24 21 [2] 2b 3b [2] 35 26 [2] 37 27 [2] 2c 21 [2] 30 26 [2] 2c 09 }

  condition:
    any of them
}
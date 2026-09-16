rule TTP_XOR_QUAD_CurrentVersionRun_7347 {
  strings:
    $key_7347 = { 20 28 [2] 04 26 [2] 2f 0a [2] 01 28 [2] 15 33 [2] 1a 29 [2] 04 34 [2] 06 35 [2] 1d 33 [2] 01 34 [2] 1d 1b }

  condition:
    any of them
}
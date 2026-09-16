rule TTP_XOR_QUAD_CurrentVersionRun_7357 {
  strings:
    $key_7357 = { 20 38 [2] 04 36 [2] 2f 1a [2] 01 38 [2] 15 23 [2] 1a 39 [2] 04 24 [2] 06 25 [2] 1d 23 [2] 01 24 [2] 1d 0b }

  condition:
    any of them
}
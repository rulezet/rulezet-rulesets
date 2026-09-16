rule TTP_XOR_QUAD_CurrentVersionRun_6f57 {
  strings:
    $key_6f57 = { 3c 38 [2] 18 36 [2] 33 1a [2] 1d 38 [2] 09 23 [2] 06 39 [2] 18 24 [2] 1a 25 [2] 01 23 [2] 1d 24 [2] 01 0b }

  condition:
    any of them
}
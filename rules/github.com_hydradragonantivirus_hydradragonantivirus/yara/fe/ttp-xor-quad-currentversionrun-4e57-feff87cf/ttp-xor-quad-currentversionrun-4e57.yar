rule TTP_XOR_QUAD_CurrentVersionRun_4e57 {
  strings:
    $key_4e57 = { 1d 38 [2] 39 36 [2] 12 1a [2] 3c 38 [2] 28 23 [2] 27 39 [2] 39 24 [2] 3b 25 [2] 20 23 [2] 3c 24 [2] 20 0b }

  condition:
    any of them
}
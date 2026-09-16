rule TTP_XOR_QUAD_CurrentVersionRun_5f57 {
  strings:
    $key_5f57 = { 0c 38 [2] 28 36 [2] 03 1a [2] 2d 38 [2] 39 23 [2] 36 39 [2] 28 24 [2] 2a 25 [2] 31 23 [2] 2d 24 [2] 31 0b }

  condition:
    any of them
}
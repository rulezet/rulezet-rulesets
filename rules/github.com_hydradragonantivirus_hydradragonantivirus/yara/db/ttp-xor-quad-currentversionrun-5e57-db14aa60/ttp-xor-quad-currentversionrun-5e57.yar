rule TTP_XOR_QUAD_CurrentVersionRun_5e57 {
  strings:
    $key_5e57 = { 0d 38 [2] 29 36 [2] 02 1a [2] 2c 38 [2] 38 23 [2] 37 39 [2] 29 24 [2] 2b 25 [2] 30 23 [2] 2c 24 [2] 30 0b }

  condition:
    any of them
}
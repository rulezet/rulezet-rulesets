rule TTP_XOR_QUAD_CurrentVersionRun_5b57 {
  strings:
    $key_5b57 = { 08 38 [2] 2c 36 [2] 07 1a [2] 29 38 [2] 3d 23 [2] 32 39 [2] 2c 24 [2] 2e 25 [2] 35 23 [2] 29 24 [2] 35 0b }

  condition:
    any of them
}
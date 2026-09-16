rule TTP_XOR_QUAD_CurrentVersionRun_5e37 {
  strings:
    $key_5e37 = { 0d 58 [2] 29 56 [2] 02 7a [2] 2c 58 [2] 38 43 [2] 37 59 [2] 29 44 [2] 2b 45 [2] 30 43 [2] 2c 44 [2] 30 6b }

  condition:
    any of them
}
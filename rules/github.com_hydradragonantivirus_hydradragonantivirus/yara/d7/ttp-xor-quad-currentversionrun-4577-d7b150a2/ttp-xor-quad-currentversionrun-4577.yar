rule TTP_XOR_QUAD_CurrentVersionRun_4577 {
  strings:
    $key_4577 = { 16 18 [2] 32 16 [2] 19 3a [2] 37 18 [2] 23 03 [2] 2c 19 [2] 32 04 [2] 30 05 [2] 2b 03 [2] 37 04 [2] 2b 2b }

  condition:
    any of them
}
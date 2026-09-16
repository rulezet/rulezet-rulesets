rule TTP_XOR_QUAD_CurrentVersionRun_5b47 {
  strings:
    $key_5b47 = { 08 28 [2] 2c 26 [2] 07 0a [2] 29 28 [2] 3d 33 [2] 32 29 [2] 2c 34 [2] 2e 35 [2] 35 33 [2] 29 34 [2] 35 1b }

  condition:
    any of them
}
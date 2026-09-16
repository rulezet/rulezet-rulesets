rule TTP_XOR_QUAD_CurrentVersionRun_5b79 {
  strings:
    $key_5b79 = { 08 16 [2] 2c 18 [2] 07 34 [2] 29 16 [2] 3d 0d [2] 32 17 [2] 2c 0a [2] 2e 0b [2] 35 0d [2] 29 0a [2] 35 25 }

  condition:
    any of them
}
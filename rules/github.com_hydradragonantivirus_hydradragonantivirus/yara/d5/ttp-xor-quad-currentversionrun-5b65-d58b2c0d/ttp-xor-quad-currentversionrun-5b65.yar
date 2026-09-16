rule TTP_XOR_QUAD_CurrentVersionRun_5b65 {
  strings:
    $key_5b65 = { 08 0a [2] 2c 04 [2] 07 28 [2] 29 0a [2] 3d 11 [2] 32 0b [2] 2c 16 [2] 2e 17 [2] 35 11 [2] 29 16 [2] 35 39 }

  condition:
    any of them
}
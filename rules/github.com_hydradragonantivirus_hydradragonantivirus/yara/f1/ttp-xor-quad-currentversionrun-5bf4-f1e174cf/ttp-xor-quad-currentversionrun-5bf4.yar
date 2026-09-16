rule TTP_XOR_QUAD_CurrentVersionRun_5bf4 {
  strings:
    $key_5bf4 = { 08 9b [2] 2c 95 [2] 07 b9 [2] 29 9b [2] 3d 80 [2] 32 9a [2] 2c 87 [2] 2e 86 [2] 35 80 [2] 29 87 [2] 35 a8 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_5be8 {
  strings:
    $key_5be8 = { 08 87 [2] 2c 89 [2] 07 a5 [2] 29 87 [2] 3d 9c [2] 32 86 [2] 2c 9b [2] 2e 9a [2] 35 9c [2] 29 9b [2] 35 b4 }

  condition:
    any of them
}
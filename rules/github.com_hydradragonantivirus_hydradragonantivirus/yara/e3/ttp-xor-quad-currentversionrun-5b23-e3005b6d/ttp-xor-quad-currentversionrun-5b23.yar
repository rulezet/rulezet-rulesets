rule TTP_XOR_QUAD_CurrentVersionRun_5b23 {
  strings:
    $key_5b23 = { 08 4c [2] 2c 42 [2] 07 6e [2] 29 4c [2] 3d 57 [2] 32 4d [2] 2c 50 [2] 2e 51 [2] 35 57 [2] 29 50 [2] 35 7f }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_5b13 {
  strings:
    $key_5b13 = { 08 7c [2] 2c 72 [2] 07 5e [2] 29 7c [2] 3d 67 [2] 32 7d [2] 2c 60 [2] 2e 61 [2] 35 67 [2] 29 60 [2] 35 4f }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_5b63 {
  strings:
    $key_5b63 = { 08 0c [2] 2c 02 [2] 07 2e [2] 29 0c [2] 3d 17 [2] 32 0d [2] 2c 10 [2] 2e 11 [2] 35 17 [2] 29 10 [2] 35 3f }

  condition:
    any of them
}
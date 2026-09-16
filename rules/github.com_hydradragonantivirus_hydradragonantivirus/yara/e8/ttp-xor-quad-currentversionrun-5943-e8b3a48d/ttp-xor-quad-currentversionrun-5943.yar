rule TTP_XOR_QUAD_CurrentVersionRun_5943 {
  strings:
    $key_5943 = { 0a 2c [2] 2e 22 [2] 05 0e [2] 2b 2c [2] 3f 37 [2] 30 2d [2] 2e 30 [2] 2c 31 [2] 37 37 [2] 2b 30 [2] 37 1f }

  condition:
    any of them
}
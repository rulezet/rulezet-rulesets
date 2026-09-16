rule TTP_XOR_QUAD_CurrentVersionRun_4223 {
  strings:
    $key_4223 = { 11 4c [2] 35 42 [2] 1e 6e [2] 30 4c [2] 24 57 [2] 2b 4d [2] 35 50 [2] 37 51 [2] 2c 57 [2] 30 50 [2] 2c 7f }

  condition:
    any of them
}
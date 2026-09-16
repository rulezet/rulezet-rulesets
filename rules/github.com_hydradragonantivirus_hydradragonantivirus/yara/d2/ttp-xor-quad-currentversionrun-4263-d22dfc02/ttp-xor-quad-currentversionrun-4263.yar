rule TTP_XOR_QUAD_CurrentVersionRun_4263 {
  strings:
    $key_4263 = { 11 0c [2] 35 02 [2] 1e 2e [2] 30 0c [2] 24 17 [2] 2b 0d [2] 35 10 [2] 37 11 [2] 2c 17 [2] 30 10 [2] 2c 3f }

  condition:
    any of them
}
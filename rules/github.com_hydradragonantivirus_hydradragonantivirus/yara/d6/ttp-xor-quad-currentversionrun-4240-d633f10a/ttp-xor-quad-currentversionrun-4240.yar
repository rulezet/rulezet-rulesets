rule TTP_XOR_QUAD_CurrentVersionRun_4240 {
  strings:
    $key_4240 = { 11 2f [2] 35 21 [2] 1e 0d [2] 30 2f [2] 24 34 [2] 2b 2e [2] 35 33 [2] 37 32 [2] 2c 34 [2] 30 33 [2] 2c 1c }

  condition:
    any of them
}
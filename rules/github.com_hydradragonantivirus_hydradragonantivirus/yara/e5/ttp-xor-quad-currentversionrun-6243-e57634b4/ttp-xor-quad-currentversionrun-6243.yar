rule TTP_XOR_QUAD_CurrentVersionRun_6243 {
  strings:
    $key_6243 = { 31 2c [2] 15 22 [2] 3e 0e [2] 10 2c [2] 04 37 [2] 0b 2d [2] 15 30 [2] 17 31 [2] 0c 37 [2] 10 30 [2] 0c 1f }

  condition:
    any of them
}
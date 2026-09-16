rule TTP_XOR_QUAD_CurrentVersionRun_4943 {
  strings:
    $key_4943 = { 1a 2c [2] 3e 22 [2] 15 0e [2] 3b 2c [2] 2f 37 [2] 20 2d [2] 3e 30 [2] 3c 31 [2] 27 37 [2] 3b 30 [2] 27 1f }

  condition:
    any of them
}
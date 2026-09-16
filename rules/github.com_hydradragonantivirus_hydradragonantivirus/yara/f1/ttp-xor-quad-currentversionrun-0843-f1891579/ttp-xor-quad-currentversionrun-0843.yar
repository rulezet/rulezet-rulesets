rule TTP_XOR_QUAD_CurrentVersionRun_0843 {
  strings:
    $key_0843 = { 5b 2c [2] 7f 22 [2] 54 0e [2] 7a 2c [2] 6e 37 [2] 61 2d [2] 7f 30 [2] 7d 31 [2] 66 37 [2] 7a 30 [2] 66 1f }

  condition:
    any of them
}
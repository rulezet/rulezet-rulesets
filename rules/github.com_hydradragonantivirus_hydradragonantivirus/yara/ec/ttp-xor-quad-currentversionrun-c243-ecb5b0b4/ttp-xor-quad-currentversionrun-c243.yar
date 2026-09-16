rule TTP_XOR_QUAD_CurrentVersionRun_c243 {
  strings:
    $key_c243 = { 91 2c [2] b5 22 [2] 9e 0e [2] b0 2c [2] a4 37 [2] ab 2d [2] b5 30 [2] b7 31 [2] ac 37 [2] b0 30 [2] ac 1f }

  condition:
    any of them
}
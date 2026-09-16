rule TTP_XOR_QUAD_CurrentVersionRun_c043 {
  strings:
    $key_c043 = { 93 2c [2] b7 22 [2] 9c 0e [2] b2 2c [2] a6 37 [2] a9 2d [2] b7 30 [2] b5 31 [2] ae 37 [2] b2 30 [2] ae 1f }

  condition:
    any of them
}
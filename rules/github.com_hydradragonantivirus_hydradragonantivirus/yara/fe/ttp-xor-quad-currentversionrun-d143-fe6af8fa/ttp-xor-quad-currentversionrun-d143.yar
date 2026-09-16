rule TTP_XOR_QUAD_CurrentVersionRun_d143 {
  strings:
    $key_d143 = { 82 2c [2] a6 22 [2] 8d 0e [2] a3 2c [2] b7 37 [2] b8 2d [2] a6 30 [2] a4 31 [2] bf 37 [2] a3 30 [2] bf 1f }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_d243 {
  strings:
    $key_d243 = { 81 2c [2] a5 22 [2] 8e 0e [2] a0 2c [2] b4 37 [2] bb 2d [2] a5 30 [2] a7 31 [2] bc 37 [2] a0 30 [2] bc 1f }

  condition:
    any of them
}
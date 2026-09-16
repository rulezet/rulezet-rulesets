rule TTP_XOR_QUAD_CurrentVersionRun_d543 {
  strings:
    $key_d543 = { 86 2c [2] a2 22 [2] 89 0e [2] a7 2c [2] b3 37 [2] bc 2d [2] a2 30 [2] a0 31 [2] bb 37 [2] a7 30 [2] bb 1f }

  condition:
    any of them
}
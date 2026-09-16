rule TTP_XOR_QUAD_CurrentVersionRun_d2c1 {
  strings:
    $key_d2c1 = { 81 ae [2] a5 a0 [2] 8e 8c [2] a0 ae [2] b4 b5 [2] bb af [2] a5 b2 [2] a7 b3 [2] bc b5 [2] a0 b2 [2] bc 9d }

  condition:
    any of them
}
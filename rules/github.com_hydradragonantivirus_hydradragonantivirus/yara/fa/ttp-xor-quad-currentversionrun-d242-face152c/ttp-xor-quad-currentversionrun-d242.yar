rule TTP_XOR_QUAD_CurrentVersionRun_d242 {
  strings:
    $key_d242 = { 81 2d [2] a5 23 [2] 8e 0f [2] a0 2d [2] b4 36 [2] bb 2c [2] a5 31 [2] a7 30 [2] bc 36 [2] a0 31 [2] bc 1e }

  condition:
    any of them
}
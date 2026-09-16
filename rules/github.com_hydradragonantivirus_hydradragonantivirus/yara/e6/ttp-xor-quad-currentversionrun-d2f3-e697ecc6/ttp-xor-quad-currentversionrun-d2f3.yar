rule TTP_XOR_QUAD_CurrentVersionRun_d2f3 {
  strings:
    $key_d2f3 = { 81 9c [2] a5 92 [2] 8e be [2] a0 9c [2] b4 87 [2] bb 9d [2] a5 80 [2] a7 81 [2] bc 87 [2] a0 80 [2] bc af }

  condition:
    any of them
}
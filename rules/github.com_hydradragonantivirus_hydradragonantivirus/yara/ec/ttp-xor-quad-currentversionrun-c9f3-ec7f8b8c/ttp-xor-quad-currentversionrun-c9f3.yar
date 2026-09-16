rule TTP_XOR_QUAD_CurrentVersionRun_c9f3 {
  strings:
    $key_c9f3 = { 9a 9c [2] be 92 [2] 95 be [2] bb 9c [2] af 87 [2] a0 9d [2] be 80 [2] bc 81 [2] a7 87 [2] bb 80 [2] a7 af }

  condition:
    any of them
}
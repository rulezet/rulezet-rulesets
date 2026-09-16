rule TTP_XOR_QUAD_CurrentVersionRun_daf3 {
  strings:
    $key_daf3 = { 89 9c [2] ad 92 [2] 86 be [2] a8 9c [2] bc 87 [2] b3 9d [2] ad 80 [2] af 81 [2] b4 87 [2] a8 80 [2] b4 af }

  condition:
    any of them
}
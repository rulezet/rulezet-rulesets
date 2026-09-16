rule TTP_XOR_QUAD_CurrentVersionRun_d5f7 {
  strings:
    $key_d5f7 = { 86 98 [2] a2 96 [2] 89 ba [2] a7 98 [2] b3 83 [2] bc 99 [2] a2 84 [2] a0 85 [2] bb 83 [2] a7 84 [2] bb ab }

  condition:
    any of them
}
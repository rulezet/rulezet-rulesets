rule TTP_XOR_QUAD_CurrentVersionRun_c9f7 {
  strings:
    $key_c9f7 = { 9a 98 [2] be 96 [2] 95 ba [2] bb 98 [2] af 83 [2] a0 99 [2] be 84 [2] bc 85 [2] a7 83 [2] bb 84 [2] a7 ab }

  condition:
    any of them
}
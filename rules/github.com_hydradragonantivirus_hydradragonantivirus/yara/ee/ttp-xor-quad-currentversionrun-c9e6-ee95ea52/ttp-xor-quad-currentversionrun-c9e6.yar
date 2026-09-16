rule TTP_XOR_QUAD_CurrentVersionRun_c9e6 {
  strings:
    $key_c9e6 = { 9a 89 [2] be 87 [2] 95 ab [2] bb 89 [2] af 92 [2] a0 88 [2] be 95 [2] bc 94 [2] a7 92 [2] bb 95 [2] a7 ba }

  condition:
    any of them
}
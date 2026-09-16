rule TTP_XOR_QUAD_CurrentVersionRun_da61 {
  strings:
    $key_da61 = { 89 0e [2] ad 00 [2] 86 2c [2] a8 0e [2] bc 15 [2] b3 0f [2] ad 12 [2] af 13 [2] b4 15 [2] a8 12 [2] b4 3d }

  condition:
    any of them
}
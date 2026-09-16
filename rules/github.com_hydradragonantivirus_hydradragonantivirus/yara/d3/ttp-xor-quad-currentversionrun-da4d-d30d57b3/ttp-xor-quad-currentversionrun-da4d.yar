rule TTP_XOR_QUAD_CurrentVersionRun_da4d {
  strings:
    $key_da4d = { 89 22 [2] ad 2c [2] 86 00 [2] a8 22 [2] bc 39 [2] b3 23 [2] ad 3e [2] af 3f [2] b4 39 [2] a8 3e [2] b4 11 }

  condition:
    any of them
}
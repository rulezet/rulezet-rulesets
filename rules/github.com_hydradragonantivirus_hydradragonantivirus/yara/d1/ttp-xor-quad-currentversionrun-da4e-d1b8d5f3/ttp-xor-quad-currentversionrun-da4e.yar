rule TTP_XOR_QUAD_CurrentVersionRun_da4e {
  strings:
    $key_da4e = { 89 21 [2] ad 2f [2] 86 03 [2] a8 21 [2] bc 3a [2] b3 20 [2] ad 3d [2] af 3c [2] b4 3a [2] a8 3d [2] b4 12 }

  condition:
    any of them
}
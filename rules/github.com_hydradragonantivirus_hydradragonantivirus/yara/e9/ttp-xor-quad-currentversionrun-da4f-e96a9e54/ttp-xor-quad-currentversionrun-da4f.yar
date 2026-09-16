rule TTP_XOR_QUAD_CurrentVersionRun_da4f {
  strings:
    $key_da4f = { 89 20 [2] ad 2e [2] 86 02 [2] a8 20 [2] bc 3b [2] b3 21 [2] ad 3c [2] af 3d [2] b4 3b [2] a8 3c [2] b4 13 }

  condition:
    any of them
}
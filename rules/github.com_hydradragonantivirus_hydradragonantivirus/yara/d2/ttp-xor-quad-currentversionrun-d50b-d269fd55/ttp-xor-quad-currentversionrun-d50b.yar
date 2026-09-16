rule TTP_XOR_QUAD_CurrentVersionRun_d50b {
  strings:
    $key_d50b = { 86 64 [2] a2 6a [2] 89 46 [2] a7 64 [2] b3 7f [2] bc 65 [2] a2 78 [2] a0 79 [2] bb 7f [2] a7 78 [2] bb 57 }

  condition:
    any of them
}
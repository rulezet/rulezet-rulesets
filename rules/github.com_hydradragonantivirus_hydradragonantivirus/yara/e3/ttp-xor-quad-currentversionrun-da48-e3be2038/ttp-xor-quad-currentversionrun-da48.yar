rule TTP_XOR_QUAD_CurrentVersionRun_da48 {
  strings:
    $key_da48 = { 89 27 [2] ad 29 [2] 86 05 [2] a8 27 [2] bc 3c [2] b3 26 [2] ad 3b [2] af 3a [2] b4 3c [2] a8 3b [2] b4 14 }

  condition:
    any of them
}
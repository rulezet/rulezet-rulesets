rule TTP_XOR_QUAD_CurrentVersionRun_da64 {
  strings:
    $key_da64 = { 89 0b [2] ad 05 [2] 86 29 [2] a8 0b [2] bc 10 [2] b3 0a [2] ad 17 [2] af 16 [2] b4 10 [2] a8 17 [2] b4 38 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_da74 {
  strings:
    $key_da74 = { 89 1b [2] ad 15 [2] 86 39 [2] a8 1b [2] bc 00 [2] b3 1a [2] ad 07 [2] af 06 [2] b4 00 [2] a8 07 [2] b4 28 }

  condition:
    any of them
}
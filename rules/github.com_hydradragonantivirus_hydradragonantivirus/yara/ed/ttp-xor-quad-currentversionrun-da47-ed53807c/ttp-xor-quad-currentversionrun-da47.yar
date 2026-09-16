rule TTP_XOR_QUAD_CurrentVersionRun_da47 {
  strings:
    $key_da47 = { 89 28 [2] ad 26 [2] 86 0a [2] a8 28 [2] bc 33 [2] b3 29 [2] ad 34 [2] af 35 [2] b4 33 [2] a8 34 [2] b4 1b }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_da34 {
  strings:
    $key_da34 = { 89 5b [2] ad 55 [2] 86 79 [2] a8 5b [2] bc 40 [2] b3 5a [2] ad 47 [2] af 46 [2] b4 40 [2] a8 47 [2] b4 68 }

  condition:
    any of them
}
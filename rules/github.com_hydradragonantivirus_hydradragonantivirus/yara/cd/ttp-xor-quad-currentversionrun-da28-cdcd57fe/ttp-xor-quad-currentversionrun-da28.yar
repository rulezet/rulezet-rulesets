rule TTP_XOR_QUAD_CurrentVersionRun_da28 {
  strings:
    $key_da28 = { 89 47 [2] ad 49 [2] 86 65 [2] a8 47 [2] bc 5c [2] b3 46 [2] ad 5b [2] af 5a [2] b4 5c [2] a8 5b [2] b4 74 }

  condition:
    any of them
}
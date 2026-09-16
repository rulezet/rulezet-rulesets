rule TTP_XOR_QUAD_CurrentVersionRun_da35 {
  strings:
    $key_da35 = { 89 5a [2] ad 54 [2] 86 78 [2] a8 5a [2] bc 41 [2] b3 5b [2] ad 46 [2] af 47 [2] b4 41 [2] a8 46 [2] b4 69 }

  condition:
    any of them
}
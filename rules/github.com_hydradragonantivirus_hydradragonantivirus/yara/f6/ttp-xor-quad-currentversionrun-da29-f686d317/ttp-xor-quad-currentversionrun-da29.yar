rule TTP_XOR_QUAD_CurrentVersionRun_da29 {
  strings:
    $key_da29 = { 89 46 [2] ad 48 [2] 86 64 [2] a8 46 [2] bc 5d [2] b3 47 [2] ad 5a [2] af 5b [2] b4 5d [2] a8 5a [2] b4 75 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_da0b {
  strings:
    $key_da0b = { 89 64 [2] ad 6a [2] 86 46 [2] a8 64 [2] bc 7f [2] b3 65 [2] ad 78 [2] af 79 [2] b4 7f [2] a8 78 [2] b4 57 }

  condition:
    any of them
}
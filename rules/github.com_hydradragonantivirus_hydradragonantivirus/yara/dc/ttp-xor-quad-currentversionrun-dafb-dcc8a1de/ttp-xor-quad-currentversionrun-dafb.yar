rule TTP_XOR_QUAD_CurrentVersionRun_dafb {
  strings:
    $key_dafb = { 89 94 [2] ad 9a [2] 86 b6 [2] a8 94 [2] bc 8f [2] b3 95 [2] ad 88 [2] af 89 [2] b4 8f [2] a8 88 [2] b4 a7 }

  condition:
    any of them
}
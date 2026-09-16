rule TTP_XOR_QUAD_CurrentVersionRun_c9e4 {
  strings:
    $key_c9e4 = { 9a 8b [2] be 85 [2] 95 a9 [2] bb 8b [2] af 90 [2] a0 8a [2] be 97 [2] bc 96 [2] a7 90 [2] bb 97 [2] a7 b8 }

  condition:
    any of them
}
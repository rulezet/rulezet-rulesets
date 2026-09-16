rule TTP_XOR_QUAD_CurrentVersionRun_c9f8 {
  strings:
    $key_c9f8 = { 9a 97 [2] be 99 [2] 95 b5 [2] bb 97 [2] af 8c [2] a0 96 [2] be 8b [2] bc 8a [2] a7 8c [2] bb 8b [2] a7 a4 }

  condition:
    any of them
}
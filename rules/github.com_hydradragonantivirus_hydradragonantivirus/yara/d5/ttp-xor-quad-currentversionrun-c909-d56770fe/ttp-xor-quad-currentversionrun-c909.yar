rule TTP_XOR_QUAD_CurrentVersionRun_c909 {
  strings:
    $key_c909 = { 9a 66 [2] be 68 [2] 95 44 [2] bb 66 [2] af 7d [2] a0 67 [2] be 7a [2] bc 7b [2] a7 7d [2] bb 7a [2] a7 55 }

  condition:
    any of them
}
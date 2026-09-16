rule TTP_XOR_QUAD_CurrentVersionRun_c948 {
  strings:
    $key_c948 = { 9a 27 [2] be 29 [2] 95 05 [2] bb 27 [2] af 3c [2] a0 26 [2] be 3b [2] bc 3a [2] a7 3c [2] bb 3b [2] a7 14 }

  condition:
    any of them
}
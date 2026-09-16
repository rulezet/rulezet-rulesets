rule TTP_XOR_QUAD_CurrentVersionRun_d204 {
  strings:
    $key_d204 = { 81 6b [2] a5 65 [2] 8e 49 [2] a0 6b [2] b4 70 [2] bb 6a [2] a5 77 [2] a7 76 [2] bc 70 [2] a0 77 [2] bc 58 }

  condition:
    any of them
}
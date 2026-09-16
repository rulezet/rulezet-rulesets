rule TTP_XOR_QUAD_CurrentVersionRun_d205 {
  strings:
    $key_d205 = { 81 6a [2] a5 64 [2] 8e 48 [2] a0 6a [2] b4 71 [2] bb 6b [2] a5 76 [2] a7 77 [2] bc 71 [2] a0 76 [2] bc 59 }

  condition:
    any of them
}
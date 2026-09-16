rule TTP_XOR_QUAD_CurrentVersionRun_d239 {
  strings:
    $key_d239 = { 81 56 [2] a5 58 [2] 8e 74 [2] a0 56 [2] b4 4d [2] bb 57 [2] a5 4a [2] a7 4b [2] bc 4d [2] a0 4a [2] bc 65 }

  condition:
    any of them
}
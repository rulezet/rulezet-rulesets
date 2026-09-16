rule TTP_XOR_QUAD_CurrentVersionRun_d21b {
  strings:
    $key_d21b = { 81 74 [2] a5 7a [2] 8e 56 [2] a0 74 [2] b4 6f [2] bb 75 [2] a5 68 [2] a7 69 [2] bc 6f [2] a0 68 [2] bc 47 }

  condition:
    any of them
}
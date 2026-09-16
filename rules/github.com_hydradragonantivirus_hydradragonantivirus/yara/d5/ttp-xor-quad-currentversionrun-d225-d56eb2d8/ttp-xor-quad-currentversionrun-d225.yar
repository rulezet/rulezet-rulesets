rule TTP_XOR_QUAD_CurrentVersionRun_d225 {
  strings:
    $key_d225 = { 81 4a [2] a5 44 [2] 8e 68 [2] a0 4a [2] b4 51 [2] bb 4b [2] a5 56 [2] a7 57 [2] bc 51 [2] a0 56 [2] bc 79 }

  condition:
    any of them
}
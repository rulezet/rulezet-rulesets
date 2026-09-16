rule TTP_XOR_QUAD_CurrentVersionRun_d515 {
  strings:
    $key_d515 = { 86 7a [2] a2 74 [2] 89 58 [2] a7 7a [2] b3 61 [2] bc 7b [2] a2 66 [2] a0 67 [2] bb 61 [2] a7 66 [2] bb 49 }

  condition:
    any of them
}
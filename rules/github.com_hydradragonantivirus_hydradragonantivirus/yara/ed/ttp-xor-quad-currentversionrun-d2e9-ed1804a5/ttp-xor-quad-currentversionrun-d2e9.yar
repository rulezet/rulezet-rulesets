rule TTP_XOR_QUAD_CurrentVersionRun_d2e9 {
  strings:
    $key_d2e9 = { 81 86 [2] a5 88 [2] 8e a4 [2] a0 86 [2] b4 9d [2] bb 87 [2] a5 9a [2] a7 9b [2] bc 9d [2] a0 9a [2] bc b5 }

  condition:
    any of them
}
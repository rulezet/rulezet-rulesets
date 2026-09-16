rule TTP_XOR_QUAD_CurrentVersionRun_d5e8 {
  strings:
    $key_d5e8 = { 86 87 [2] a2 89 [2] 89 a5 [2] a7 87 [2] b3 9c [2] bc 86 [2] a2 9b [2] a0 9a [2] bb 9c [2] a7 9b [2] bb b4 }

  condition:
    any of them
}
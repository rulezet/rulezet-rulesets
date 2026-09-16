rule TTP_XOR_QUAD_CurrentVersionRun_cee8 {
  strings:
    $key_cee8 = { 9d 87 [2] b9 89 [2] 92 a5 [2] bc 87 [2] a8 9c [2] a7 86 [2] b9 9b [2] bb 9a [2] a0 9c [2] bc 9b [2] a0 b4 }

  condition:
    any of them
}
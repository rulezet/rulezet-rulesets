rule TTP_XOR_QUAD_CurrentVersionRun_d5f9 {
  strings:
    $key_d5f9 = { 86 96 [2] a2 98 [2] 89 b4 [2] a7 96 [2] b3 8d [2] bc 97 [2] a2 8a [2] a0 8b [2] bb 8d [2] a7 8a [2] bb a5 }

  condition:
    any of them
}
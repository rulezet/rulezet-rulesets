rule TTP_XOR_QUAD_CurrentVersionRun_cbe8 {
  strings:
    $key_cbe8 = { 98 87 [2] bc 89 [2] 97 a5 [2] b9 87 [2] ad 9c [2] a2 86 [2] bc 9b [2] be 9a [2] a5 9c [2] b9 9b [2] a5 b4 }

  condition:
    any of them
}
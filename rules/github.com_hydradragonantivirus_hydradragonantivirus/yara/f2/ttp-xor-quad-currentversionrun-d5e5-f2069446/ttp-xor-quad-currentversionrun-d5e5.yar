rule TTP_XOR_QUAD_CurrentVersionRun_d5e5 {
  strings:
    $key_d5e5 = { 86 8a [2] a2 84 [2] 89 a8 [2] a7 8a [2] b3 91 [2] bc 8b [2] a2 96 [2] a0 97 [2] bb 91 [2] a7 96 [2] bb b9 }

  condition:
    any of them
}
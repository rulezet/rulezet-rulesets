rule TTP_XOR_QUAD_CurrentVersionRun_d50a {
  strings:
    $key_d50a = { 86 65 [2] a2 6b [2] 89 47 [2] a7 65 [2] b3 7e [2] bc 64 [2] a2 79 [2] a0 78 [2] bb 7e [2] a7 79 [2] bb 56 }

  condition:
    any of them
}
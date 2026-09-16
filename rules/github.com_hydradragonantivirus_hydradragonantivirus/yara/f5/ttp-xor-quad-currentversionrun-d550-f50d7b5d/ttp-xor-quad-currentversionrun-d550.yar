rule TTP_XOR_QUAD_CurrentVersionRun_d550 {
  strings:
    $key_d550 = { 86 3f [2] a2 31 [2] 89 1d [2] a7 3f [2] b3 24 [2] bc 3e [2] a2 23 [2] a0 22 [2] bb 24 [2] a7 23 [2] bb 0c }

  condition:
    any of them
}
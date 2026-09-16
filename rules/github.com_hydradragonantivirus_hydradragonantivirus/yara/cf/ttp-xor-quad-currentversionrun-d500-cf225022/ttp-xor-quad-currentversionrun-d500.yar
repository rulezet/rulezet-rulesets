rule TTP_XOR_QUAD_CurrentVersionRun_d500 {
  strings:
    $key_d500 = { 86 6f [2] a2 61 [2] 89 4d [2] a7 6f [2] b3 74 [2] bc 6e [2] a2 73 [2] a0 72 [2] bb 74 [2] a7 73 [2] bb 5c }

  condition:
    any of them
}
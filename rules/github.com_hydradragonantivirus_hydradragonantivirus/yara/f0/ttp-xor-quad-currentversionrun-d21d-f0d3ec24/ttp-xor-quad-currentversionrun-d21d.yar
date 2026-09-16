rule TTP_XOR_QUAD_CurrentVersionRun_d21d {
  strings:
    $key_d21d = { 81 72 [2] a5 7c [2] 8e 50 [2] a0 72 [2] b4 69 [2] bb 73 [2] a5 6e [2] a7 6f [2] bc 69 [2] a0 6e [2] bc 41 }

  condition:
    any of them
}
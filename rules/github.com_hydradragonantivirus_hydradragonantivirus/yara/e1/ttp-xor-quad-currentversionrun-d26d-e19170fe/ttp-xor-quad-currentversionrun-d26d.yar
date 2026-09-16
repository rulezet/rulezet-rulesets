rule TTP_XOR_QUAD_CurrentVersionRun_d26d {
  strings:
    $key_d26d = { 81 02 [2] a5 0c [2] 8e 20 [2] a0 02 [2] b4 19 [2] bb 03 [2] a5 1e [2] a7 1f [2] bc 19 [2] a0 1e [2] bc 31 }

  condition:
    any of them
}
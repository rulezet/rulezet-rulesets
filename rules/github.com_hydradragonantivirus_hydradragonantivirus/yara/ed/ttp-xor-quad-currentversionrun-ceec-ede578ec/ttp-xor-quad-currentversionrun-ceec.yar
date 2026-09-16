rule TTP_XOR_QUAD_CurrentVersionRun_ceec {
  strings:
    $key_ceec = { 9d 83 [2] b9 8d [2] 92 a1 [2] bc 83 [2] a8 98 [2] a7 82 [2] b9 9f [2] bb 9e [2] a0 98 [2] bc 9f [2] a0 b0 }

  condition:
    any of them
}
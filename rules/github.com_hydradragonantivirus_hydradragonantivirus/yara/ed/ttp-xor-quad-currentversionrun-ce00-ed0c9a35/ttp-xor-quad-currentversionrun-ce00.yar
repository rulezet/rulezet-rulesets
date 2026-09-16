rule TTP_XOR_QUAD_CurrentVersionRun_ce00 {
  strings:
    $key_ce00 = { 9d 6f [2] b9 61 [2] 92 4d [2] bc 6f [2] a8 74 [2] a7 6e [2] b9 73 [2] bb 72 [2] a0 74 [2] bc 73 [2] a0 5c }

  condition:
    any of them
}
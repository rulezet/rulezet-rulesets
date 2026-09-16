rule TTP_XOR_QUAD_CurrentVersionRun_ce20 {
  strings:
    $key_ce20 = { 9d 4f [2] b9 41 [2] 92 6d [2] bc 4f [2] a8 54 [2] a7 4e [2] b9 53 [2] bb 52 [2] a0 54 [2] bc 53 [2] a0 7c }

  condition:
    any of them
}
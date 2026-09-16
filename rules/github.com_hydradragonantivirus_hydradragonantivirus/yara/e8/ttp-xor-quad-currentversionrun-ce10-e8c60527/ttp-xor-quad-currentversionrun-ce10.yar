rule TTP_XOR_QUAD_CurrentVersionRun_ce10 {
  strings:
    $key_ce10 = { 9d 7f [2] b9 71 [2] 92 5d [2] bc 7f [2] a8 64 [2] a7 7e [2] b9 63 [2] bb 62 [2] a0 64 [2] bc 63 [2] a0 4c }

  condition:
    any of them
}
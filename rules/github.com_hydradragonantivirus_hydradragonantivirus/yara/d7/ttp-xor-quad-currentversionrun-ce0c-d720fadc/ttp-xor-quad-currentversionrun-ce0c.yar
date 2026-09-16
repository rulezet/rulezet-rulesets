rule TTP_XOR_QUAD_CurrentVersionRun_ce0c {
  strings:
    $key_ce0c = { 9d 63 [2] b9 6d [2] 92 41 [2] bc 63 [2] a8 78 [2] a7 62 [2] b9 7f [2] bb 7e [2] a0 78 [2] bc 7f [2] a0 50 }

  condition:
    any of them
}
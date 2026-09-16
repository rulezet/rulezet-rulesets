rule TTP_XOR_QUAD_CurrentVersionRun_ce50 {
  strings:
    $key_ce50 = { 9d 3f [2] b9 31 [2] 92 1d [2] bc 3f [2] a8 24 [2] a7 3e [2] b9 23 [2] bb 22 [2] a0 24 [2] bc 23 [2] a0 0c }

  condition:
    any of them
}
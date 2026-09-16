rule TTP_XOR_QUAD_CurrentVersionRun_ce11 {
  strings:
    $key_ce11 = { 9d 7e [2] b9 70 [2] 92 5c [2] bc 7e [2] a8 65 [2] a7 7f [2] b9 62 [2] bb 63 [2] a0 65 [2] bc 62 [2] a0 4d }

  condition:
    any of them
}
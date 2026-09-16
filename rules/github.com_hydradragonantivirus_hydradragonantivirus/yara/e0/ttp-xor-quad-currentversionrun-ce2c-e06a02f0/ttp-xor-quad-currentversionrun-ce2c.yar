rule TTP_XOR_QUAD_CurrentVersionRun_ce2c {
  strings:
    $key_ce2c = { 9d 43 [2] b9 4d [2] 92 61 [2] bc 43 [2] a8 58 [2] a7 42 [2] b9 5f [2] bb 5e [2] a0 58 [2] bc 5f [2] a0 70 }

  condition:
    any of them
}
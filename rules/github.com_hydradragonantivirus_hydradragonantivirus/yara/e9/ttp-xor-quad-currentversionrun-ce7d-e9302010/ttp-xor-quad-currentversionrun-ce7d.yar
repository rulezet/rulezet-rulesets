rule TTP_XOR_QUAD_CurrentVersionRun_ce7d {
  strings:
    $key_ce7d = { 9d 12 [2] b9 1c [2] 92 30 [2] bc 12 [2] a8 09 [2] a7 13 [2] b9 0e [2] bb 0f [2] a0 09 [2] bc 0e [2] a0 21 }

  condition:
    any of them
}
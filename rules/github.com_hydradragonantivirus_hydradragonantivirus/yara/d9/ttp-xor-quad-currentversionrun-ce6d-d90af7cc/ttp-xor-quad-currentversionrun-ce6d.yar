rule TTP_XOR_QUAD_CurrentVersionRun_ce6d {
  strings:
    $key_ce6d = { 9d 02 [2] b9 0c [2] 92 20 [2] bc 02 [2] a8 19 [2] a7 03 [2] b9 1e [2] bb 1f [2] a0 19 [2] bc 1e [2] a0 31 }

  condition:
    any of them
}
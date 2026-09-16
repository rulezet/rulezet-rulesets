rule TTP_XOR_QUAD_CurrentVersionRun_ce6a {
  strings:
    $key_ce6a = { 9d 05 [2] b9 0b [2] 92 27 [2] bc 05 [2] a8 1e [2] a7 04 [2] b9 19 [2] bb 18 [2] a0 1e [2] bc 19 [2] a0 36 }

  condition:
    any of them
}
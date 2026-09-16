rule TTP_XOR_QUAD_CurrentVersionRun_ce4a {
  strings:
    $key_ce4a = { 9d 25 [2] b9 2b [2] 92 07 [2] bc 25 [2] a8 3e [2] a7 24 [2] b9 39 [2] bb 38 [2] a0 3e [2] bc 39 [2] a0 16 }

  condition:
    any of them
}
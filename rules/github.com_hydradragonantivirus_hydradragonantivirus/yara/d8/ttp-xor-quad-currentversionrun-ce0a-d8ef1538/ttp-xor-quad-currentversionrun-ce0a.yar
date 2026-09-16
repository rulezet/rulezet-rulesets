rule TTP_XOR_QUAD_CurrentVersionRun_ce0a {
  strings:
    $key_ce0a = { 9d 65 [2] b9 6b [2] 92 47 [2] bc 65 [2] a8 7e [2] a7 64 [2] b9 79 [2] bb 78 [2] a0 7e [2] bc 79 [2] a0 56 }

  condition:
    any of them
}
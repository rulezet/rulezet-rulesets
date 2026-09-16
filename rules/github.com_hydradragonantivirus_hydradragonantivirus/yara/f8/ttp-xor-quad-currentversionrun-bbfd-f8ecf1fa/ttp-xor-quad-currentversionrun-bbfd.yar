rule TTP_XOR_QUAD_CurrentVersionRun_bbfd {
  strings:
    $key_bbfd = { e8 92 [2] cc 9c [2] e7 b0 [2] c9 92 [2] dd 89 [2] d2 93 [2] cc 8e [2] ce 8f [2] d5 89 [2] c9 8e [2] d5 a1 }

  condition:
    any of them
}
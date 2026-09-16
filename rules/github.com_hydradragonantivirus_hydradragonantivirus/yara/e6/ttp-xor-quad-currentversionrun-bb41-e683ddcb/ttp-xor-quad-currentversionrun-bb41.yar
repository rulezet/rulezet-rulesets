rule TTP_XOR_QUAD_CurrentVersionRun_bb41 {
  strings:
    $key_bb41 = { e8 2e [2] cc 20 [2] e7 0c [2] c9 2e [2] dd 35 [2] d2 2f [2] cc 32 [2] ce 33 [2] d5 35 [2] c9 32 [2] d5 1d }

  condition:
    any of them
}
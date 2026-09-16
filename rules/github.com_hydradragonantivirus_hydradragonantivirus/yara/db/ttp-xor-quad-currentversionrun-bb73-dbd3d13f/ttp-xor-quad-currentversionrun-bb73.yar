rule TTP_XOR_QUAD_CurrentVersionRun_bb73 {
  strings:
    $key_bb73 = { e8 1c [2] cc 12 [2] e7 3e [2] c9 1c [2] dd 07 [2] d2 1d [2] cc 00 [2] ce 01 [2] d5 07 [2] c9 00 [2] d5 2f }

  condition:
    any of them
}
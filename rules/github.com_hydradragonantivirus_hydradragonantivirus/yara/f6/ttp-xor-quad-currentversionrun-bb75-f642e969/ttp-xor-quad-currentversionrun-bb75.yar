rule TTP_XOR_QUAD_CurrentVersionRun_bb75 {
  strings:
    $key_bb75 = { e8 1a [2] cc 14 [2] e7 38 [2] c9 1a [2] dd 01 [2] d2 1b [2] cc 06 [2] ce 07 [2] d5 01 [2] c9 06 [2] d5 29 }

  condition:
    any of them
}
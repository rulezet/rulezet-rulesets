rule TTP_XOR_QUAD_CurrentVersionRun_bb74 {
  strings:
    $key_bb74 = { e8 1b [2] cc 15 [2] e7 39 [2] c9 1b [2] dd 00 [2] d2 1a [2] cc 07 [2] ce 06 [2] d5 00 [2] c9 07 [2] d5 28 }

  condition:
    any of them
}
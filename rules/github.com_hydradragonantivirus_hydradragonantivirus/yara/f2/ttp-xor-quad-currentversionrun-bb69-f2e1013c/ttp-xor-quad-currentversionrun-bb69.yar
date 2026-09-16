rule TTP_XOR_QUAD_CurrentVersionRun_bb69 {
  strings:
    $key_bb69 = { e8 06 [2] cc 08 [2] e7 24 [2] c9 06 [2] dd 1d [2] d2 07 [2] cc 1a [2] ce 1b [2] d5 1d [2] c9 1a [2] d5 35 }

  condition:
    any of them
}
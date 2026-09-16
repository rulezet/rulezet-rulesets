rule TTP_XOR_QUAD_CurrentVersionRun_bb59 {
  strings:
    $key_bb59 = { e8 36 [2] cc 38 [2] e7 14 [2] c9 36 [2] dd 2d [2] d2 37 [2] cc 2a [2] ce 2b [2] d5 2d [2] c9 2a [2] d5 05 }

  condition:
    any of them
}
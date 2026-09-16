rule TTP_XOR_QUAD_CurrentVersionRun_bb18 {
  strings:
    $key_bb18 = { e8 77 [2] cc 79 [2] e7 55 [2] c9 77 [2] dd 6c [2] d2 76 [2] cc 6b [2] ce 6a [2] d5 6c [2] c9 6b [2] d5 44 }

  condition:
    any of them
}
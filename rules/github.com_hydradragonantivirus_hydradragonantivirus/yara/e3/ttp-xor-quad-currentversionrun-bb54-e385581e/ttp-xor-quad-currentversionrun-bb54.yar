rule TTP_XOR_QUAD_CurrentVersionRun_bb54 {
  strings:
    $key_bb54 = { e8 3b [2] cc 35 [2] e7 19 [2] c9 3b [2] dd 20 [2] d2 3a [2] cc 27 [2] ce 26 [2] d5 20 [2] c9 27 [2] d5 08 }

  condition:
    any of them
}
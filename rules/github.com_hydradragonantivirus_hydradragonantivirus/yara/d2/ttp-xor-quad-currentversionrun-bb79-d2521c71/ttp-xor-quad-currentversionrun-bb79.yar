rule TTP_XOR_QUAD_CurrentVersionRun_bb79 {
  strings:
    $key_bb79 = { e8 16 [2] cc 18 [2] e7 34 [2] c9 16 [2] dd 0d [2] d2 17 [2] cc 0a [2] ce 0b [2] d5 0d [2] c9 0a [2] d5 25 }

  condition:
    any of them
}
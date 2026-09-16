rule TTP_XOR_QUAD_CurrentVersionRun_bb4c {
  strings:
    $key_bb4c = { e8 23 [2] cc 2d [2] e7 01 [2] c9 23 [2] dd 38 [2] d2 22 [2] cc 3f [2] ce 3e [2] d5 38 [2] c9 3f [2] d5 10 }

  condition:
    any of them
}
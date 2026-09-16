rule TTP_XOR_QUAD_CurrentVersionRun_bb4d {
  strings:
    $key_bb4d = { e8 22 [2] cc 2c [2] e7 00 [2] c9 22 [2] dd 39 [2] d2 23 [2] cc 3e [2] ce 3f [2] d5 39 [2] c9 3e [2] d5 11 }

  condition:
    any of them
}
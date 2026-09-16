rule TTP_XOR_QUAD_CurrentVersionRun_bb33 {
  strings:
    $key_bb33 = { e8 5c [2] cc 52 [2] e7 7e [2] c9 5c [2] dd 47 [2] d2 5d [2] cc 40 [2] ce 41 [2] d5 47 [2] c9 40 [2] d5 6f }

  condition:
    any of them
}
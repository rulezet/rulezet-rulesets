rule TTP_XOR_QUAD_CurrentVersionRun_bb4f {
  strings:
    $key_bb4f = { e8 20 [2] cc 2e [2] e7 02 [2] c9 20 [2] dd 3b [2] d2 21 [2] cc 3c [2] ce 3d [2] d5 3b [2] c9 3c [2] d5 13 }

  condition:
    any of them
}
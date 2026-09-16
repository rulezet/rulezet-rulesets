rule TTP_XOR_QUAD_CurrentVersionRun_bb3f {
  strings:
    $key_bb3f = { e8 50 [2] cc 5e [2] e7 72 [2] c9 50 [2] dd 4b [2] d2 51 [2] cc 4c [2] ce 4d [2] d5 4b [2] c9 4c [2] d5 63 }

  condition:
    any of them
}
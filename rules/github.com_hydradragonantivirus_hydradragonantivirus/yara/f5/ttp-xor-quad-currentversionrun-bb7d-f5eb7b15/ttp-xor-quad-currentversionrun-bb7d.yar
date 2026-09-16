rule TTP_XOR_QUAD_CurrentVersionRun_bb7d {
  strings:
    $key_bb7d = { e8 12 [2] cc 1c [2] e7 30 [2] c9 12 [2] dd 09 [2] d2 13 [2] cc 0e [2] ce 0f [2] d5 09 [2] c9 0e [2] d5 21 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_bb7c {
  strings:
    $key_bb7c = { e8 13 [2] cc 1d [2] e7 31 [2] c9 13 [2] dd 08 [2] d2 12 [2] cc 0f [2] ce 0e [2] d5 08 [2] c9 0f [2] d5 20 }

  condition:
    any of them
}
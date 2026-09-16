rule TTP_XOR_QUAD_CurrentVersionRun_bb0e {
  strings:
    $key_bb0e = { e8 61 [2] cc 6f [2] e7 43 [2] c9 61 [2] dd 7a [2] d2 60 [2] cc 7d [2] ce 7c [2] d5 7a [2] c9 7d [2] d5 52 }

  condition:
    any of them
}
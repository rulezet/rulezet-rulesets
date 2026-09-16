rule TTP_XOR_QUAD_CurrentVersionRun_bb1e {
  strings:
    $key_bb1e = { e8 71 [2] cc 7f [2] e7 53 [2] c9 71 [2] dd 6a [2] d2 70 [2] cc 6d [2] ce 6c [2] d5 6a [2] c9 6d [2] d5 42 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_bb2e {
  strings:
    $key_bb2e = { e8 41 [2] cc 4f [2] e7 63 [2] c9 41 [2] dd 5a [2] d2 40 [2] cc 5d [2] ce 5c [2] d5 5a [2] c9 5d [2] d5 72 }

  condition:
    any of them
}
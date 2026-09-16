rule TTP_XOR_QUAD_CurrentVersionRun_bb2f {
  strings:
    $key_bb2f = { e8 40 [2] cc 4e [2] e7 62 [2] c9 40 [2] dd 5b [2] d2 41 [2] cc 5c [2] ce 5d [2] d5 5b [2] c9 5c [2] d5 73 }

  condition:
    any of them
}
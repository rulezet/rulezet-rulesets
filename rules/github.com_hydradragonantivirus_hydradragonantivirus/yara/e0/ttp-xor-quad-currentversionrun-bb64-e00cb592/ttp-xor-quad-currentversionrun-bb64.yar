rule TTP_XOR_QUAD_CurrentVersionRun_bb64 {
  strings:
    $key_bb64 = { e8 0b [2] cc 05 [2] e7 29 [2] c9 0b [2] dd 10 [2] d2 0a [2] cc 17 [2] ce 16 [2] d5 10 [2] c9 17 [2] d5 38 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_bb78 {
  strings:
    $key_bb78 = { e8 17 [2] cc 19 [2] e7 35 [2] c9 17 [2] dd 0c [2] d2 16 [2] cc 0b [2] ce 0a [2] d5 0c [2] c9 0b [2] d5 24 }

  condition:
    any of them
}
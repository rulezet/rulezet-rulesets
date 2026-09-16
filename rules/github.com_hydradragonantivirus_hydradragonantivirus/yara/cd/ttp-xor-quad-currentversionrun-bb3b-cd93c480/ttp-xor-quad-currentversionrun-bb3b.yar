rule TTP_XOR_QUAD_CurrentVersionRun_bb3b {
  strings:
    $key_bb3b = { e8 54 [2] cc 5a [2] e7 76 [2] c9 54 [2] dd 4f [2] d2 55 [2] cc 48 [2] ce 49 [2] d5 4f [2] c9 48 [2] d5 67 }

  condition:
    any of them
}
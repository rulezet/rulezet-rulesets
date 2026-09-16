rule TTP_XOR_QUAD_CurrentVersionRun_bb66 {
  strings:
    $key_bb66 = { e8 09 [2] cc 07 [2] e7 2b [2] c9 09 [2] dd 12 [2] d2 08 [2] cc 15 [2] ce 14 [2] d5 12 [2] c9 15 [2] d5 3a }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_bb72 {
  strings:
    $key_bb72 = { e8 1d [2] cc 13 [2] e7 3f [2] c9 1d [2] dd 06 [2] d2 1c [2] cc 01 [2] ce 00 [2] d5 06 [2] c9 01 [2] d5 2e }

  condition:
    any of them
}
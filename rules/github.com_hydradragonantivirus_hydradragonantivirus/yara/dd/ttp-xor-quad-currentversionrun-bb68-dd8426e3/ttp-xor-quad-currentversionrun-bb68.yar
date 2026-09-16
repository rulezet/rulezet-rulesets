rule TTP_XOR_QUAD_CurrentVersionRun_bb68 {
  strings:
    $key_bb68 = { e8 07 [2] cc 09 [2] e7 25 [2] c9 07 [2] dd 1c [2] d2 06 [2] cc 1b [2] ce 1a [2] d5 1c [2] c9 1b [2] d5 34 }

  condition:
    any of them
}
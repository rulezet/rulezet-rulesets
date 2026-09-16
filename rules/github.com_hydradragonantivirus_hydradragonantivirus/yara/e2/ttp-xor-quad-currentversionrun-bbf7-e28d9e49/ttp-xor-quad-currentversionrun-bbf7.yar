rule TTP_XOR_QUAD_CurrentVersionRun_bbf7 {
  strings:
    $key_bbf7 = { e8 98 [2] cc 96 [2] e7 ba [2] c9 98 [2] dd 83 [2] d2 99 [2] cc 84 [2] ce 85 [2] d5 83 [2] c9 84 [2] d5 ab }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_bbf3 {
  strings:
    $key_bbf3 = { e8 9c [2] cc 92 [2] e7 be [2] c9 9c [2] dd 87 [2] d2 9d [2] cc 80 [2] ce 81 [2] d5 87 [2] c9 80 [2] d5 af }

  condition:
    any of them
}
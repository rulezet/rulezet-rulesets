rule TTP_XOR_QUAD_CurrentVersionRun_aa63 {
  strings:
    $key_aa63 = { f9 0c [2] dd 02 [2] f6 2e [2] d8 0c [2] cc 17 [2] c3 0d [2] dd 10 [2] df 11 [2] c4 17 [2] d8 10 [2] c4 3f }

  condition:
    any of them
}
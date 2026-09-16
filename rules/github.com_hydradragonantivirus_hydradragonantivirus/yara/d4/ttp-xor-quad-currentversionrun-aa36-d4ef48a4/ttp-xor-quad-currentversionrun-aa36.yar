rule TTP_XOR_QUAD_CurrentVersionRun_aa36 {
  strings:
    $key_aa36 = { f9 59 [2] dd 57 [2] f6 7b [2] d8 59 [2] cc 42 [2] c3 58 [2] dd 45 [2] df 44 [2] c4 42 [2] d8 45 [2] c4 6a }

  condition:
    any of them
}
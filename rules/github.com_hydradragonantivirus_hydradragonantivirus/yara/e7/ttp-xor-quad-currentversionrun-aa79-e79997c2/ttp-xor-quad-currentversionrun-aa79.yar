rule TTP_XOR_QUAD_CurrentVersionRun_aa79 {
  strings:
    $key_aa79 = { f9 16 [2] dd 18 [2] f6 34 [2] d8 16 [2] cc 0d [2] c3 17 [2] dd 0a [2] df 0b [2] c4 0d [2] d8 0a [2] c4 25 }

  condition:
    any of them
}
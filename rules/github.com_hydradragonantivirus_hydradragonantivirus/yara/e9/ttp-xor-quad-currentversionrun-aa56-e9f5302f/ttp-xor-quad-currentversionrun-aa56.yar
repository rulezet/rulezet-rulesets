rule TTP_XOR_QUAD_CurrentVersionRun_aa56 {
  strings:
    $key_aa56 = { f9 39 [2] dd 37 [2] f6 1b [2] d8 39 [2] cc 22 [2] c3 38 [2] dd 25 [2] df 24 [2] c4 22 [2] d8 25 [2] c4 0a }

  condition:
    any of them
}
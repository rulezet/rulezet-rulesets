rule TTP_XOR_QUAD_CurrentVersionRun_aa06 {
  strings:
    $key_aa06 = { f9 69 [2] dd 67 [2] f6 4b [2] d8 69 [2] cc 72 [2] c3 68 [2] dd 75 [2] df 74 [2] c4 72 [2] d8 75 [2] c4 5a }

  condition:
    any of them
}
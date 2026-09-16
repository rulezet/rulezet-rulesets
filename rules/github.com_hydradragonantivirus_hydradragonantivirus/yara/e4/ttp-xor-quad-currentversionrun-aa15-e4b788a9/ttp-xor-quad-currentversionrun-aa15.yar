rule TTP_XOR_QUAD_CurrentVersionRun_aa15 {
  strings:
    $key_aa15 = { f9 7a [2] dd 74 [2] f6 58 [2] d8 7a [2] cc 61 [2] c3 7b [2] dd 66 [2] df 67 [2] c4 61 [2] d8 66 [2] c4 49 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_aa48 {
  strings:
    $key_aa48 = { f9 27 [2] dd 29 [2] f6 05 [2] d8 27 [2] cc 3c [2] c3 26 [2] dd 3b [2] df 3a [2] c4 3c [2] d8 3b [2] c4 14 }

  condition:
    any of them
}
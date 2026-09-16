rule TTP_XOR_QUAD_CurrentVersionRun_aa66 {
  strings:
    $key_aa66 = { f9 09 [2] dd 07 [2] f6 2b [2] d8 09 [2] cc 12 [2] c3 08 [2] dd 15 [2] df 14 [2] c4 12 [2] d8 15 [2] c4 3a }

  condition:
    any of them
}
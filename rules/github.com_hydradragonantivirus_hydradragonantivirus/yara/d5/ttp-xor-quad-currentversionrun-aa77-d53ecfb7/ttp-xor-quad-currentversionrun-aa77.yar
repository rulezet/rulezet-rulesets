rule TTP_XOR_QUAD_CurrentVersionRun_aa77 {
  strings:
    $key_aa77 = { f9 18 [2] dd 16 [2] f6 3a [2] d8 18 [2] cc 03 [2] c3 19 [2] dd 04 [2] df 05 [2] c4 03 [2] d8 04 [2] c4 2b }

  condition:
    any of them
}
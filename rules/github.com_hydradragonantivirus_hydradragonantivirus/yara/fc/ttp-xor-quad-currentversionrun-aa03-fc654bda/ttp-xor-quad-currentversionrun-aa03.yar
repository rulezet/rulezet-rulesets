rule TTP_XOR_QUAD_CurrentVersionRun_aa03 {
  strings:
    $key_aa03 = { f9 6c [2] dd 62 [2] f6 4e [2] d8 6c [2] cc 77 [2] c3 6d [2] dd 70 [2] df 71 [2] c4 77 [2] d8 70 [2] c4 5f }

  condition:
    any of them
}
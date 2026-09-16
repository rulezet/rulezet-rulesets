rule TTP_XOR_QUAD_CurrentVersionRun_aa22 {
  strings:
    $key_aa22 = { f9 4d [2] dd 43 [2] f6 6f [2] d8 4d [2] cc 56 [2] c3 4c [2] dd 51 [2] df 50 [2] c4 56 [2] d8 51 [2] c4 7e }

  condition:
    any of them
}
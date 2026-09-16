rule TTP_XOR_QUAD_CurrentVersionRun_aa62 {
  strings:
    $key_aa62 = { f9 0d [2] dd 03 [2] f6 2f [2] d8 0d [2] cc 16 [2] c3 0c [2] dd 11 [2] df 10 [2] c4 16 [2] d8 11 [2] c4 3e }

  condition:
    any of them
}
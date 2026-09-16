rule TTP_XOR_QUAD_CurrentVersionRun_aa2c {
  strings:
    $key_aa2c = { f9 43 [2] dd 4d [2] f6 61 [2] d8 43 [2] cc 58 [2] c3 42 [2] dd 5f [2] df 5e [2] c4 58 [2] d8 5f [2] c4 70 }

  condition:
    any of them
}
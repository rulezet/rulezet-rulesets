rule TTP_XOR_QUAD_CurrentVersionRun_aa4c {
  strings:
    $key_aa4c = { f9 23 [2] dd 2d [2] f6 01 [2] d8 23 [2] cc 38 [2] c3 22 [2] dd 3f [2] df 3e [2] c4 38 [2] d8 3f [2] c4 10 }

  condition:
    any of them
}
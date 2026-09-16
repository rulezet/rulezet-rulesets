rule TTP_XOR_QUAD_CurrentVersionRun_aa50 {
  strings:
    $key_aa50 = { f9 3f [2] dd 31 [2] f6 1d [2] d8 3f [2] cc 24 [2] c3 3e [2] dd 23 [2] df 22 [2] c4 24 [2] d8 23 [2] c4 0c }

  condition:
    any of them
}
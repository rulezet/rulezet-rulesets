rule TTP_XOR_QUAD_CurrentVersionRun_aa34 {
  strings:
    $key_aa34 = { f9 5b [2] dd 55 [2] f6 79 [2] d8 5b [2] cc 40 [2] c3 5a [2] dd 47 [2] df 46 [2] c4 40 [2] d8 47 [2] c4 68 }

  condition:
    any of them
}
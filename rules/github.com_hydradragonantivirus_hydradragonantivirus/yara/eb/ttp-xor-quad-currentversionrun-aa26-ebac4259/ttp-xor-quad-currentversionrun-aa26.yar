rule TTP_XOR_QUAD_CurrentVersionRun_aa26 {
  strings:
    $key_aa26 = { f9 49 [2] dd 47 [2] f6 6b [2] d8 49 [2] cc 52 [2] c3 48 [2] dd 55 [2] df 54 [2] c4 52 [2] d8 55 [2] c4 7a }

  condition:
    any of them
}
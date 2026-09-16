rule TTP_XOR_QUAD_CurrentVersionRun_aa4b {
  strings:
    $key_aa4b = { f9 24 [2] dd 2a [2] f6 06 [2] d8 24 [2] cc 3f [2] c3 25 [2] dd 38 [2] df 39 [2] c4 3f [2] d8 38 [2] c4 17 }

  condition:
    any of them
}
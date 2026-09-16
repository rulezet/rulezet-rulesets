rule TTP_XOR_QUAD_CurrentVersionRun_aa6b {
  strings:
    $key_aa6b = { f9 04 [2] dd 0a [2] f6 26 [2] d8 04 [2] cc 1f [2] c3 05 [2] dd 18 [2] df 19 [2] c4 1f [2] d8 18 [2] c4 37 }

  condition:
    any of them
}
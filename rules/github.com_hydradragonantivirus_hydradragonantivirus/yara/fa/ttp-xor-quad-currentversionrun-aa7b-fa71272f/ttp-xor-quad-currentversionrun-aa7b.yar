rule TTP_XOR_QUAD_CurrentVersionRun_aa7b {
  strings:
    $key_aa7b = { f9 14 [2] dd 1a [2] f6 36 [2] d8 14 [2] cc 0f [2] c3 15 [2] dd 08 [2] df 09 [2] c4 0f [2] d8 08 [2] c4 27 }

  condition:
    any of them
}
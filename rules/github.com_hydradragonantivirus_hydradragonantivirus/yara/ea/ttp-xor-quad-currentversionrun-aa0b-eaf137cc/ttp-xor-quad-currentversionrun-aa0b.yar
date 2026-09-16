rule TTP_XOR_QUAD_CurrentVersionRun_aa0b {
  strings:
    $key_aa0b = { f9 64 [2] dd 6a [2] f6 46 [2] d8 64 [2] cc 7f [2] c3 65 [2] dd 78 [2] df 79 [2] c4 7f [2] d8 78 [2] c4 57 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_aafb {
  strings:
    $key_aafb = { f9 94 [2] dd 9a [2] f6 b6 [2] d8 94 [2] cc 8f [2] c3 95 [2] dd 88 [2] df 89 [2] c4 8f [2] d8 88 [2] c4 a7 }

  condition:
    any of them
}
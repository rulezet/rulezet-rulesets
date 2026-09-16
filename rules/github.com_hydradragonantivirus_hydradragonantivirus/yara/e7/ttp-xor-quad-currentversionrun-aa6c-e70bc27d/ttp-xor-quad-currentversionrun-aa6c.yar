rule TTP_XOR_QUAD_CurrentVersionRun_aa6c {
  strings:
    $key_aa6c = { f9 03 [2] dd 0d [2] f6 21 [2] d8 03 [2] cc 18 [2] c3 02 [2] dd 1f [2] df 1e [2] c4 18 [2] d8 1f [2] c4 30 }

  condition:
    any of them
}
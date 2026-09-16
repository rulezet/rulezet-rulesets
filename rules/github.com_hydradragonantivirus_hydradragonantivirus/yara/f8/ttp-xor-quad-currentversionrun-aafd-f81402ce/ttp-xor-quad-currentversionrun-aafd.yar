rule TTP_XOR_QUAD_CurrentVersionRun_aafd {
  strings:
    $key_aafd = { f9 92 [2] dd 9c [2] f6 b0 [2] d8 92 [2] cc 89 [2] c3 93 [2] dd 8e [2] df 8f [2] c4 89 [2] d8 8e [2] c4 a1 }

  condition:
    any of them
}
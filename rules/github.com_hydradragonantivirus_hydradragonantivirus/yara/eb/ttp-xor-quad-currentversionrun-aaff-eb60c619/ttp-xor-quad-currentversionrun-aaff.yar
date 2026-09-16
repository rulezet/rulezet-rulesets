rule TTP_XOR_QUAD_CurrentVersionRun_aaff {
  strings:
    $key_aaff = { f9 90 [2] dd 9e [2] f6 b2 [2] d8 90 [2] cc 8b [2] c3 91 [2] dd 8c [2] df 8d [2] c4 8b [2] d8 8c [2] c4 a3 }

  condition:
    any of them
}
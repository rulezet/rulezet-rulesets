rule TTP_XOR_QUAD_CurrentVersionRun_aa10 {
  strings:
    $key_aa10 = { f9 7f [2] dd 71 [2] f6 5d [2] d8 7f [2] cc 64 [2] c3 7e [2] dd 63 [2] df 62 [2] c4 64 [2] d8 63 [2] c4 4c }

  condition:
    any of them
}
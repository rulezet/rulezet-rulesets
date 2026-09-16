rule TTP_XOR_QUAD_CurrentVersionRun_aab8 {
  strings:
    $key_aab8 = { f9 d7 [2] dd d9 [2] f6 f5 [2] d8 d7 [2] cc cc [2] c3 d6 [2] dd cb [2] df ca [2] c4 cc [2] d8 cb [2] c4 e4 }

  condition:
    any of them
}
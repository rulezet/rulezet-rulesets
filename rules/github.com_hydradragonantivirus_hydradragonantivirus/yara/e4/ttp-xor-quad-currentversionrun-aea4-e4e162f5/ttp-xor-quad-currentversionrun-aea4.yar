rule TTP_XOR_QUAD_CurrentVersionRun_aea4 {
  strings:
    $key_aea4 = { fd cb [2] d9 c5 [2] f2 e9 [2] dc cb [2] c8 d0 [2] c7 ca [2] d9 d7 [2] db d6 [2] c0 d0 [2] dc d7 [2] c0 f8 }

  condition:
    any of them
}
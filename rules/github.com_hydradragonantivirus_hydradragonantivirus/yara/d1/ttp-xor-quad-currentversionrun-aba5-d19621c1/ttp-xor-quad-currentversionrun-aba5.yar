rule TTP_XOR_QUAD_CurrentVersionRun_aba5 {
  strings:
    $key_aba5 = { f8 ca [2] dc c4 [2] f7 e8 [2] d9 ca [2] cd d1 [2] c2 cb [2] dc d6 [2] de d7 [2] c5 d1 [2] d9 d6 [2] c5 f9 }

  condition:
    any of them
}
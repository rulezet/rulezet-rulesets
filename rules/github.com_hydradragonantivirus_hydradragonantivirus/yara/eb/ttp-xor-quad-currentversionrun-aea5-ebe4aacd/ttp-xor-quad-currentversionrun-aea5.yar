rule TTP_XOR_QUAD_CurrentVersionRun_aea5 {
  strings:
    $key_aea5 = { fd ca [2] d9 c4 [2] f2 e8 [2] dc ca [2] c8 d1 [2] c7 cb [2] d9 d6 [2] db d7 [2] c0 d1 [2] dc d6 [2] c0 f9 }

  condition:
    any of them
}
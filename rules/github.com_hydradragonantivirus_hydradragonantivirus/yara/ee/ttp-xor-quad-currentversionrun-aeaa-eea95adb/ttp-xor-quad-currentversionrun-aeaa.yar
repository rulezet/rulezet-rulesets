rule TTP_XOR_QUAD_CurrentVersionRun_aeaa {
  strings:
    $key_aeaa = { fd c5 [2] d9 cb [2] f2 e7 [2] dc c5 [2] c8 de [2] c7 c4 [2] d9 d9 [2] db d8 [2] c0 de [2] dc d9 [2] c0 f6 }

  condition:
    any of them
}
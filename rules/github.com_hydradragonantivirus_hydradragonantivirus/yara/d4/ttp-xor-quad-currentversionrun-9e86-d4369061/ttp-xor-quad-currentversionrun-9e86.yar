rule TTP_XOR_QUAD_CurrentVersionRun_9e86 {
  strings:
    $key_9e86 = { cd e9 [2] e9 e7 [2] c2 cb [2] ec e9 [2] f8 f2 [2] f7 e8 [2] e9 f5 [2] eb f4 [2] f0 f2 [2] ec f5 [2] f0 da }

  condition:
    any of them
}
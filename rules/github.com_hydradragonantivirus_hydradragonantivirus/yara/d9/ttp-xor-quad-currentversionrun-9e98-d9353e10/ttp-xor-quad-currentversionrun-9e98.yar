rule TTP_XOR_QUAD_CurrentVersionRun_9e98 {
  strings:
    $key_9e98 = { cd f7 [2] e9 f9 [2] c2 d5 [2] ec f7 [2] f8 ec [2] f7 f6 [2] e9 eb [2] eb ea [2] f0 ec [2] ec eb [2] f0 c4 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_9e85 {
  strings:
    $key_9e85 = { cd ea [2] e9 e4 [2] c2 c8 [2] ec ea [2] f8 f1 [2] f7 eb [2] e9 f6 [2] eb f7 [2] f0 f1 [2] ec f6 [2] f0 d9 }

  condition:
    any of them
}
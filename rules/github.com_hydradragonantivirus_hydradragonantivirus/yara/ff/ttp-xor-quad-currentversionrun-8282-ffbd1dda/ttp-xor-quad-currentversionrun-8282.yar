rule TTP_XOR_QUAD_CurrentVersionRun_8282 {
  strings:
    $key_8282 = { d1 ed [2] f5 e3 [2] de cf [2] f0 ed [2] e4 f6 [2] eb ec [2] f5 f1 [2] f7 f0 [2] ec f6 [2] f0 f1 [2] ec de }

  condition:
    any of them
}
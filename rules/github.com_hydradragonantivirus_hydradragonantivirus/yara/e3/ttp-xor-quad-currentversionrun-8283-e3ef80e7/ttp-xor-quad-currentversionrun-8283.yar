rule TTP_XOR_QUAD_CurrentVersionRun_8283 {
  strings:
    $key_8283 = { d1 ec [2] f5 e2 [2] de ce [2] f0 ec [2] e4 f7 [2] eb ed [2] f5 f0 [2] f7 f1 [2] ec f7 [2] f0 f0 [2] ec df }

  condition:
    any of them
}
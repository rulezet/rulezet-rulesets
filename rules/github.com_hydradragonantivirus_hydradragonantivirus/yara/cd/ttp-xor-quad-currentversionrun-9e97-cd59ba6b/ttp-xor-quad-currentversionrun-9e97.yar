rule TTP_XOR_QUAD_CurrentVersionRun_9e97 {
  strings:
    $key_9e97 = { cd f8 [2] e9 f6 [2] c2 da [2] ec f8 [2] f8 e3 [2] f7 f9 [2] e9 e4 [2] eb e5 [2] f0 e3 [2] ec e4 [2] f0 cb }

  condition:
    any of them
}
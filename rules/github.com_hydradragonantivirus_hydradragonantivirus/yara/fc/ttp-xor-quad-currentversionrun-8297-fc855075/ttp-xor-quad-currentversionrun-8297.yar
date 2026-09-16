rule TTP_XOR_QUAD_CurrentVersionRun_8297 {
  strings:
    $key_8297 = { d1 f8 [2] f5 f6 [2] de da [2] f0 f8 [2] e4 e3 [2] eb f9 [2] f5 e4 [2] f7 e5 [2] ec e3 [2] f0 e4 [2] ec cb }

  condition:
    any of them
}
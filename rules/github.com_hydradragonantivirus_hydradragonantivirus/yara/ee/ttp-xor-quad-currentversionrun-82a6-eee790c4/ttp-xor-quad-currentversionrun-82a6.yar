rule TTP_XOR_QUAD_CurrentVersionRun_82a6 {
  strings:
    $key_82a6 = { d1 c9 [2] f5 c7 [2] de eb [2] f0 c9 [2] e4 d2 [2] eb c8 [2] f5 d5 [2] f7 d4 [2] ec d2 [2] f0 d5 [2] ec fa }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_82a3 {
  strings:
    $key_82a3 = { d1 cc [2] f5 c2 [2] de ee [2] f0 cc [2] e4 d7 [2] eb cd [2] f5 d0 [2] f7 d1 [2] ec d7 [2] f0 d0 [2] ec ff }

  condition:
    any of them
}
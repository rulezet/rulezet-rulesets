rule TTP_XOR_QUAD_CurrentVersionRun_8280 {
  strings:
    $key_8280 = { d1 ef [2] f5 e1 [2] de cd [2] f0 ef [2] e4 f4 [2] eb ee [2] f5 f3 [2] f7 f2 [2] ec f4 [2] f0 f3 [2] ec dc }

  condition:
    any of them
}
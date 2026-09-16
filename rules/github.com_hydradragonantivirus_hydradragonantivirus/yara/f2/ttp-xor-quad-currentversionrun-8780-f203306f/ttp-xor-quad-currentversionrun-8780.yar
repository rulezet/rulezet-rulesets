rule TTP_XOR_QUAD_CurrentVersionRun_8780 {
  strings:
    $key_8780 = { d4 ef [2] f0 e1 [2] db cd [2] f5 ef [2] e1 f4 [2] ee ee [2] f0 f3 [2] f2 f2 [2] e9 f4 [2] f5 f3 [2] e9 dc }

  condition:
    any of them
}
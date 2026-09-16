rule TTP_XOR_QUAD_CurrentVersionRun_9686 {
  strings:
    $key_9686 = { c5 e9 [2] e1 e7 [2] ca cb [2] e4 e9 [2] f0 f2 [2] ff e8 [2] e1 f5 [2] e3 f4 [2] f8 f2 [2] e4 f5 [2] f8 da }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_9687 {
  strings:
    $key_9687 = { c5 e8 [2] e1 e6 [2] ca ca [2] e4 e8 [2] f0 f3 [2] ff e9 [2] e1 f4 [2] e3 f5 [2] f8 f3 [2] e4 f4 [2] f8 db }

  condition:
    any of them
}
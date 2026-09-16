rule TTP_XOR_QUAD_CurrentVersionRun_9cd6 {
  strings:
    $key_9cd6 = { cf b9 [2] eb b7 [2] c0 9b [2] ee b9 [2] fa a2 [2] f5 b8 [2] eb a5 [2] e9 a4 [2] f2 a2 [2] ee a5 [2] f2 8a }

  condition:
    any of them
}
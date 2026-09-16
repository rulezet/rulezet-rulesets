rule TTP_XOR_QUAD_CurrentVersionRun_9ca5 {
  strings:
    $key_9ca5 = { cf ca [2] eb c4 [2] c0 e8 [2] ee ca [2] fa d1 [2] f5 cb [2] eb d6 [2] e9 d7 [2] f2 d1 [2] ee d6 [2] f2 f9 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_9ca4 {
  strings:
    $key_9ca4 = { cf cb [2] eb c5 [2] c0 e9 [2] ee cb [2] fa d0 [2] f5 ca [2] eb d7 [2] e9 d6 [2] f2 d0 [2] ee d7 [2] f2 f8 }

  condition:
    any of them
}
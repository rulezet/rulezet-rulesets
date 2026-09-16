rule TTP_XOR_QUAD_CurrentVersionRun_99aa {
  strings:
    $key_99aa = { ca c5 [2] ee cb [2] c5 e7 [2] eb c5 [2] ff de [2] f0 c4 [2] ee d9 [2] ec d8 [2] f7 de [2] eb d9 [2] f7 f6 }

  condition:
    any of them
}
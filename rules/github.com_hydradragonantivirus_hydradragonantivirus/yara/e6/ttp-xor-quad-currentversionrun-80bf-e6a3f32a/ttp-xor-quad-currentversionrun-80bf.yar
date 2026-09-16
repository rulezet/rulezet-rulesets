rule TTP_XOR_QUAD_CurrentVersionRun_80bf {
  strings:
    $key_80bf = { d3 d0 [2] f7 de [2] dc f2 [2] f2 d0 [2] e6 cb [2] e9 d1 [2] f7 cc [2] f5 cd [2] ee cb [2] f2 cc [2] ee e3 }

  condition:
    any of them
}
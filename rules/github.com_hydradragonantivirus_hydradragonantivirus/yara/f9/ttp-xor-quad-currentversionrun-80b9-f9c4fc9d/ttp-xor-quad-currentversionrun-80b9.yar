rule TTP_XOR_QUAD_CurrentVersionRun_80b9 {
  strings:
    $key_80b9 = { d3 d6 [2] f7 d8 [2] dc f4 [2] f2 d6 [2] e6 cd [2] e9 d7 [2] f7 ca [2] f5 cb [2] ee cd [2] f2 ca [2] ee e5 }

  condition:
    any of them
}
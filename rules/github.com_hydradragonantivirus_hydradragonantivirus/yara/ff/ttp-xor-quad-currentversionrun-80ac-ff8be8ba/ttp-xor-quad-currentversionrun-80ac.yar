rule TTP_XOR_QUAD_CurrentVersionRun_80ac {
  strings:
    $key_80ac = { d3 c3 [2] f7 cd [2] dc e1 [2] f2 c3 [2] e6 d8 [2] e9 c2 [2] f7 df [2] f5 de [2] ee d8 [2] f2 df [2] ee f0 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_8098 {
  strings:
    $key_8098 = { d3 f7 [2] f7 f9 [2] dc d5 [2] f2 f7 [2] e6 ec [2] e9 f6 [2] f7 eb [2] f5 ea [2] ee ec [2] f2 eb [2] ee c4 }

  condition:
    any of them
}
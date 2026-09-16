rule TTP_XOR_QUAD_CurrentVersionRun_a8a6 {
  strings:
    $key_a8a6 = { fb c9 [2] df c7 [2] f4 eb [2] da c9 [2] ce d2 [2] c1 c8 [2] df d5 [2] dd d4 [2] c6 d2 [2] da d5 [2] c6 fa }

  condition:
    any of them
}
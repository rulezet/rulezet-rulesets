rule TTP_XOR_QUAD_CurrentVersionRun_9abb {
  strings:
    $key_9abb = { c9 d4 [2] ed da [2] c6 f6 [2] e8 d4 [2] fc cf [2] f3 d5 [2] ed c8 [2] ef c9 [2] f4 cf [2] e8 c8 [2] f4 e7 }

  condition:
    any of them
}
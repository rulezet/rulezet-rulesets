rule TTP_XOR_QUAD_CurrentVersionRun_9ab7 {
  strings:
    $key_9ab7 = { c9 d8 [2] ed d6 [2] c6 fa [2] e8 d8 [2] fc c3 [2] f3 d9 [2] ed c4 [2] ef c5 [2] f4 c3 [2] e8 c4 [2] f4 eb }

  condition:
    any of them
}
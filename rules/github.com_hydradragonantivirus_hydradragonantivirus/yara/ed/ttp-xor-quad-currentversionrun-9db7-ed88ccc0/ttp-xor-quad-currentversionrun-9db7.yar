rule TTP_XOR_QUAD_CurrentVersionRun_9db7 {
  strings:
    $key_9db7 = { ce d8 [2] ea d6 [2] c1 fa [2] ef d8 [2] fb c3 [2] f4 d9 [2] ea c4 [2] e8 c5 [2] f3 c3 [2] ef c4 [2] f3 eb }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_acb7 {
  strings:
    $key_acb7 = { ff d8 [2] db d6 [2] f0 fa [2] de d8 [2] ca c3 [2] c5 d9 [2] db c4 [2] d9 c5 [2] c2 c3 [2] de c4 [2] c2 eb }

  condition:
    any of them
}
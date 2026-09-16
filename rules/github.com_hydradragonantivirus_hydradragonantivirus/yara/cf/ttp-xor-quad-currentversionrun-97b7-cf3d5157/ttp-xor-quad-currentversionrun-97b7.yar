rule TTP_XOR_QUAD_CurrentVersionRun_97b7 {
  strings:
    $key_97b7 = { c4 d8 [2] e0 d6 [2] cb fa [2] e5 d8 [2] f1 c3 [2] fe d9 [2] e0 c4 [2] e2 c5 [2] f9 c3 [2] e5 c4 [2] f9 eb }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_93b7 {
  strings:
    $key_93b7 = { c0 d8 [2] e4 d6 [2] cf fa [2] e1 d8 [2] f5 c3 [2] fa d9 [2] e4 c4 [2] e6 c5 [2] fd c3 [2] e1 c4 [2] fd eb }

  condition:
    any of them
}
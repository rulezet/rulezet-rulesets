rule TTP_XOR_QUAD_CurrentVersionRun_9dd0 {
  strings:
    $key_9dd0 = { ce bf [2] ea b1 [2] c1 9d [2] ef bf [2] fb a4 [2] f4 be [2] ea a3 [2] e8 a2 [2] f3 a4 [2] ef a3 [2] f3 8c }

  condition:
    any of them
}
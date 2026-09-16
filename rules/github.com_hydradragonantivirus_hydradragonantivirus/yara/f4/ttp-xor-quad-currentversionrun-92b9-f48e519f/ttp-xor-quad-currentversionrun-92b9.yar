rule TTP_XOR_QUAD_CurrentVersionRun_92b9 {
  strings:
    $key_92b9 = { c1 d6 [2] e5 d8 [2] ce f4 [2] e0 d6 [2] f4 cd [2] fb d7 [2] e5 ca [2] e7 cb [2] fc cd [2] e0 ca [2] fc e5 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_87b9 {
  strings:
    $key_87b9 = { d4 d6 [2] f0 d8 [2] db f4 [2] f5 d6 [2] e1 cd [2] ee d7 [2] f0 ca [2] f2 cb [2] e9 cd [2] f5 ca [2] e9 e5 }

  condition:
    any of them
}
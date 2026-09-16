rule TTP_XOR_QUAD_CurrentVersionRun_81b9 {
  strings:
    $key_81b9 = { d2 d6 [2] f6 d8 [2] dd f4 [2] f3 d6 [2] e7 cd [2] e8 d7 [2] f6 ca [2] f4 cb [2] ef cd [2] f3 ca [2] ef e5 }

  condition:
    any of them
}
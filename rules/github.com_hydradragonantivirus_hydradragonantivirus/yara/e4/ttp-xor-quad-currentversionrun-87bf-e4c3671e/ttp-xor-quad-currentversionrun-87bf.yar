rule TTP_XOR_QUAD_CurrentVersionRun_87bf {
  strings:
    $key_87bf = { d4 d0 [2] f0 de [2] db f2 [2] f5 d0 [2] e1 cb [2] ee d1 [2] f0 cc [2] f2 cd [2] e9 cb [2] f5 cc [2] e9 e3 }

  condition:
    any of them
}
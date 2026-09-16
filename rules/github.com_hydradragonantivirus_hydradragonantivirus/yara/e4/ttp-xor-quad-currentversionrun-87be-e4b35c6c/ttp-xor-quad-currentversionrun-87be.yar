rule TTP_XOR_QUAD_CurrentVersionRun_87be {
  strings:
    $key_87be = { d4 d1 [2] f0 df [2] db f3 [2] f5 d1 [2] e1 ca [2] ee d0 [2] f0 cd [2] f2 cc [2] e9 ca [2] f5 cd [2] e9 e2 }

  condition:
    any of them
}
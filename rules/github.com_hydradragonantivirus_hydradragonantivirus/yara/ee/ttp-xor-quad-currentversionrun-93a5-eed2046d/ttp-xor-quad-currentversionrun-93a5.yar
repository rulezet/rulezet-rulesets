rule TTP_XOR_QUAD_CurrentVersionRun_93a5 {
  strings:
    $key_93a5 = { c0 ca [2] e4 c4 [2] cf e8 [2] e1 ca [2] f5 d1 [2] fa cb [2] e4 d6 [2] e6 d7 [2] fd d1 [2] e1 d6 [2] fd f9 }

  condition:
    any of them
}
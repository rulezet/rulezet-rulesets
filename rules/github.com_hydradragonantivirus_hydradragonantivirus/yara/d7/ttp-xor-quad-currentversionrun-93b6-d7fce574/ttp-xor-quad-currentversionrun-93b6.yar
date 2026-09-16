rule TTP_XOR_QUAD_CurrentVersionRun_93b6 {
  strings:
    $key_93b6 = { c0 d9 [2] e4 d7 [2] cf fb [2] e1 d9 [2] f5 c2 [2] fa d8 [2] e4 c5 [2] e6 c4 [2] fd c2 [2] e1 c5 [2] fd ea }

  condition:
    any of them
}
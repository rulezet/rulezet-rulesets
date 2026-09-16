rule TTP_XOR_QUAD_CurrentVersionRun_85ab {
  strings:
    $key_85ab = { d6 c4 [2] f2 ca [2] d9 e6 [2] f7 c4 [2] e3 df [2] ec c5 [2] f2 d8 [2] f0 d9 [2] eb df [2] f7 d8 [2] eb f7 }

  condition:
    any of them
}
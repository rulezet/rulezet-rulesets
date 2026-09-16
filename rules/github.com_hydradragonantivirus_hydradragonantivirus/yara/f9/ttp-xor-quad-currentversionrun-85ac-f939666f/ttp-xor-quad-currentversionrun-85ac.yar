rule TTP_XOR_QUAD_CurrentVersionRun_85ac {
  strings:
    $key_85ac = { d6 c3 [2] f2 cd [2] d9 e1 [2] f7 c3 [2] e3 d8 [2] ec c2 [2] f2 df [2] f0 de [2] eb d8 [2] f7 df [2] eb f0 }

  condition:
    any of them
}
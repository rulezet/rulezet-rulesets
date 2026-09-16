rule TTP_XOR_QUAD_CurrentVersionRun_96ac {
  strings:
    $key_96ac = { c5 c3 [2] e1 cd [2] ca e1 [2] e4 c3 [2] f0 d8 [2] ff c2 [2] e1 df [2] e3 de [2] f8 d8 [2] e4 df [2] f8 f0 }

  condition:
    any of them
}
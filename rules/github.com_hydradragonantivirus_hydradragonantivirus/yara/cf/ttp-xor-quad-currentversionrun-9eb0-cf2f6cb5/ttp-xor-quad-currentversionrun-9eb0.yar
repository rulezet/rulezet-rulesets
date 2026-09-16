rule TTP_XOR_QUAD_CurrentVersionRun_9eb0 {
  strings:
    $key_9eb0 = { cd df [2] e9 d1 [2] c2 fd [2] ec df [2] f8 c4 [2] f7 de [2] e9 c3 [2] eb c2 [2] f0 c4 [2] ec c3 [2] f0 ec }

  condition:
    any of them
}
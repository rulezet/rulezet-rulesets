rule TTP_XOR_QUAD_CurrentVersionRun_85b1 {
  strings:
    $key_85b1 = { d6 de [2] f2 d0 [2] d9 fc [2] f7 de [2] e3 c5 [2] ec df [2] f2 c2 [2] f0 c3 [2] eb c5 [2] f7 c2 [2] eb ed }

  condition:
    any of them
}
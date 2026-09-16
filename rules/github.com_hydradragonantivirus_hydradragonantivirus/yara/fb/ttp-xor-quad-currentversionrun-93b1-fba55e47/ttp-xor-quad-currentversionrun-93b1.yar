rule TTP_XOR_QUAD_CurrentVersionRun_93b1 {
  strings:
    $key_93b1 = { c0 de [2] e4 d0 [2] cf fc [2] e1 de [2] f5 c5 [2] fa df [2] e4 c2 [2] e6 c3 [2] fd c5 [2] e1 c2 [2] fd ed }

  condition:
    any of them
}
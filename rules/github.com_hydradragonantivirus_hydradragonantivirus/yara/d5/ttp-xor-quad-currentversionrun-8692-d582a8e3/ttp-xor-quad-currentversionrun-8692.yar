rule TTP_XOR_QUAD_CurrentVersionRun_8692 {
  strings:
    $key_8692 = { d5 fd [2] f1 f3 [2] da df [2] f4 fd [2] e0 e6 [2] ef fc [2] f1 e1 [2] f3 e0 [2] e8 e6 [2] f4 e1 [2] e8 ce }

  condition:
    any of them
}
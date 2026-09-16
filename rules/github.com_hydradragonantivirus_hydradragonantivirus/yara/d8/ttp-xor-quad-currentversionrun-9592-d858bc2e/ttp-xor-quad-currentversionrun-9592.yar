rule TTP_XOR_QUAD_CurrentVersionRun_9592 {
  strings:
    $key_9592 = { c6 fd [2] e2 f3 [2] c9 df [2] e7 fd [2] f3 e6 [2] fc fc [2] e2 e1 [2] e0 e0 [2] fb e6 [2] e7 e1 [2] fb ce }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_0492 {
  strings:
    $key_0492 = { 57 fd [2] 73 f3 [2] 58 df [2] 76 fd [2] 62 e6 [2] 6d fc [2] 73 e1 [2] 71 e0 [2] 6a e6 [2] 76 e1 [2] 6a ce }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_2292 {
  strings:
    $key_2292 = { 71 fd [2] 55 f3 [2] 7e df [2] 50 fd [2] 44 e6 [2] 4b fc [2] 55 e1 [2] 57 e0 [2] 4c e6 [2] 50 e1 [2] 4c ce }

  condition:
    any of them
}
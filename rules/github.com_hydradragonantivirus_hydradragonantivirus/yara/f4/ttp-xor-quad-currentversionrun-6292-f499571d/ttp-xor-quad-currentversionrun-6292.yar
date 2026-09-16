rule TTP_XOR_QUAD_CurrentVersionRun_6292 {
  strings:
    $key_6292 = { 31 fd [2] 15 f3 [2] 3e df [2] 10 fd [2] 04 e6 [2] 0b fc [2] 15 e1 [2] 17 e0 [2] 0c e6 [2] 10 e1 [2] 0c ce }

  condition:
    any of them
}
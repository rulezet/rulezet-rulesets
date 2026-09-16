rule TTP_XOR_QUAD_CurrentVersionRun_7392 {
  strings:
    $key_7392 = { 20 fd [2] 04 f3 [2] 2f df [2] 01 fd [2] 15 e6 [2] 1a fc [2] 04 e1 [2] 06 e0 [2] 1d e6 [2] 01 e1 [2] 1d ce }

  condition:
    any of them
}
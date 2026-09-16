rule TTP_XOR_QUAD_CurrentVersionRun_7692 {
  strings:
    $key_7692 = { 25 fd [2] 01 f3 [2] 2a df [2] 04 fd [2] 10 e6 [2] 1f fc [2] 01 e1 [2] 03 e0 [2] 18 e6 [2] 04 e1 [2] 18 ce }

  condition:
    any of them
}
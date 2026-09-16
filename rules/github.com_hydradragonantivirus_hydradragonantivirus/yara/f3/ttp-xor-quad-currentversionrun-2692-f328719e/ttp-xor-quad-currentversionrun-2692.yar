rule TTP_XOR_QUAD_CurrentVersionRun_2692 {
  strings:
    $key_2692 = { 75 fd [2] 51 f3 [2] 7a df [2] 54 fd [2] 40 e6 [2] 4f fc [2] 51 e1 [2] 53 e0 [2] 48 e6 [2] 54 e1 [2] 48 ce }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_2192 {
  strings:
    $key_2192 = { 72 fd [2] 56 f3 [2] 7d df [2] 53 fd [2] 47 e6 [2] 48 fc [2] 56 e1 [2] 54 e0 [2] 4f e6 [2] 53 e1 [2] 4f ce }

  condition:
    any of them
}
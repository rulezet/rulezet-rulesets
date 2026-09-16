rule TTP_XOR_QUAD_CurrentVersionRun_b392 {
  strings:
    $key_b392 = { e0 fd [2] c4 f3 [2] ef df [2] c1 fd [2] d5 e6 [2] da fc [2] c4 e1 [2] c6 e0 [2] dd e6 [2] c1 e1 [2] dd ce }

  condition:
    any of them
}
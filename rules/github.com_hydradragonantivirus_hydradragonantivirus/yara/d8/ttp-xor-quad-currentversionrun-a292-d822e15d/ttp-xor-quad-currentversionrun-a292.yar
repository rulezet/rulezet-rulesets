rule TTP_XOR_QUAD_CurrentVersionRun_a292 {
  strings:
    $key_a292 = { f1 fd [2] d5 f3 [2] fe df [2] d0 fd [2] c4 e6 [2] cb fc [2] d5 e1 [2] d7 e0 [2] cc e6 [2] d0 e1 [2] cc ce }

  condition:
    any of them
}
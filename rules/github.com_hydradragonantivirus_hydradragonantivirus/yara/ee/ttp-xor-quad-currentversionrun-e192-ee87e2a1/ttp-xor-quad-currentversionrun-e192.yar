rule TTP_XOR_QUAD_CurrentVersionRun_e192 {
  strings:
    $key_e192 = { b2 fd [2] 96 f3 [2] bd df [2] 93 fd [2] 87 e6 [2] 88 fc [2] 96 e1 [2] 94 e0 [2] 8f e6 [2] 93 e1 [2] 8f ce }

  condition:
    any of them
}
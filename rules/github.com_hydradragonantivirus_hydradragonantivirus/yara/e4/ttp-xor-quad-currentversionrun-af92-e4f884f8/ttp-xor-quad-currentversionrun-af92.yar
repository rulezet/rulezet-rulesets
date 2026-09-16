rule TTP_XOR_QUAD_CurrentVersionRun_af92 {
  strings:
    $key_af92 = { fc fd [2] d8 f3 [2] f3 df [2] dd fd [2] c9 e6 [2] c6 fc [2] d8 e1 [2] da e0 [2] c1 e6 [2] dd e1 [2] c1 ce }

  condition:
    any of them
}
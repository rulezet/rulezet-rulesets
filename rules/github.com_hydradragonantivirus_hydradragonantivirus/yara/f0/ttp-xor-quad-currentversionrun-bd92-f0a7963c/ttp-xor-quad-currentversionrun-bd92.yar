rule TTP_XOR_QUAD_CurrentVersionRun_bd92 {
  strings:
    $key_bd92 = { ee fd [2] ca f3 [2] e1 df [2] cf fd [2] db e6 [2] d4 fc [2] ca e1 [2] c8 e0 [2] d3 e6 [2] cf e1 [2] d3 ce }

  condition:
    any of them
}
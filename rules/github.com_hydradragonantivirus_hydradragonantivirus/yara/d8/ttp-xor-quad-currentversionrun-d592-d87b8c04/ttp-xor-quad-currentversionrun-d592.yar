rule TTP_XOR_QUAD_CurrentVersionRun_d592 {
  strings:
    $key_d592 = { 86 fd [2] a2 f3 [2] 89 df [2] a7 fd [2] b3 e6 [2] bc fc [2] a2 e1 [2] a0 e0 [2] bb e6 [2] a7 e1 [2] bb ce }

  condition:
    any of them
}
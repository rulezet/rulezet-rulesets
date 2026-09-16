rule TTP_XOR_QUAD_CurrentVersionRun_d292 {
  strings:
    $key_d292 = { 81 fd [2] a5 f3 [2] 8e df [2] a0 fd [2] b4 e6 [2] bb fc [2] a5 e1 [2] a7 e0 [2] bc e6 [2] a0 e1 [2] bc ce }

  condition:
    any of them
}
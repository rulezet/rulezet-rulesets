rule TTP_XOR_QUAD_CurrentVersionRun_c98e {
  strings:
    $key_c98e = { 9a e1 [2] be ef [2] 95 c3 [2] bb e1 [2] af fa [2] a0 e0 [2] be fd [2] bc fc [2] a7 fa [2] bb fd [2] a7 d2 }

  condition:
    any of them
}
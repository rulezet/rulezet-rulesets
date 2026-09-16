rule TTP_XOR_QUAD_CurrentVersionRun_cc89 {
  strings:
    $key_cc89 = { 9f e6 [2] bb e8 [2] 90 c4 [2] be e6 [2] aa fd [2] a5 e7 [2] bb fa [2] b9 fb [2] a2 fd [2] be fa [2] a2 d5 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_cc88 {
  strings:
    $key_cc88 = { 9f e7 [2] bb e9 [2] 90 c5 [2] be e7 [2] aa fc [2] a5 e6 [2] bb fb [2] b9 fa [2] a2 fc [2] be fb [2] a2 d4 }

  condition:
    any of them
}
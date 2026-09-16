rule TTP_XOR_QUAD_CurrentVersionRun_b994 {
  strings:
    $key_b994 = { ea fb [2] ce f5 [2] e5 d9 [2] cb fb [2] df e0 [2] d0 fa [2] ce e7 [2] cc e6 [2] d7 e0 [2] cb e7 [2] d7 c8 }

  condition:
    any of them
}
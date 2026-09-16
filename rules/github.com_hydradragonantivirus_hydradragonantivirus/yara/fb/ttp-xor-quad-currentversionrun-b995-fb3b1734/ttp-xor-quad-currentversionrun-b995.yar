rule TTP_XOR_QUAD_CurrentVersionRun_b995 {
  strings:
    $key_b995 = { ea fa [2] ce f4 [2] e5 d8 [2] cb fa [2] df e1 [2] d0 fb [2] ce e6 [2] cc e7 [2] d7 e1 [2] cb e6 [2] d7 c9 }

  condition:
    any of them
}
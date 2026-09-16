rule TTP_XOR_QUAD_CurrentVersionRun_b99b {
  strings:
    $key_b99b = { ea f4 [2] ce fa [2] e5 d6 [2] cb f4 [2] df ef [2] d0 f5 [2] ce e8 [2] cc e9 [2] d7 ef [2] cb e8 [2] d7 c7 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_ad8e {
  strings:
    $key_ad8e = { fe e1 [2] da ef [2] f1 c3 [2] df e1 [2] cb fa [2] c4 e0 [2] da fd [2] d8 fc [2] c3 fa [2] df fd [2] c3 d2 }

  condition:
    any of them
}
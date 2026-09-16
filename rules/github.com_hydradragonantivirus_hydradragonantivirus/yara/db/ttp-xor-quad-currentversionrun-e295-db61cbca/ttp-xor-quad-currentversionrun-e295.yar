rule TTP_XOR_QUAD_CurrentVersionRun_e295 {
  strings:
    $key_e295 = { b1 fa [2] 95 f4 [2] be d8 [2] 90 fa [2] 84 e1 [2] 8b fb [2] 95 e6 [2] 97 e7 [2] 8c e1 [2] 90 e6 [2] 8c c9 }

  condition:
    any of them
}
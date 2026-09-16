rule TTP_XOR_QUAD_CurrentVersionRun_3a97 {
  strings:
    $key_3a97 = { 69 f8 [2] 4d f6 [2] 66 da [2] 48 f8 [2] 5c e3 [2] 53 f9 [2] 4d e4 [2] 4f e5 [2] 54 e3 [2] 48 e4 [2] 54 cb }

  condition:
    any of them
}
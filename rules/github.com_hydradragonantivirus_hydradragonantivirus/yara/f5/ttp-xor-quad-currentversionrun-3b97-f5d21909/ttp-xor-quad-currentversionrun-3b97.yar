rule TTP_XOR_QUAD_CurrentVersionRun_3b97 {
  strings:
    $key_3b97 = { 68 f8 [2] 4c f6 [2] 67 da [2] 49 f8 [2] 5d e3 [2] 52 f9 [2] 4c e4 [2] 4e e5 [2] 55 e3 [2] 49 e4 [2] 55 cb }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_6497 {
  strings:
    $key_6497 = { 37 f8 [2] 13 f6 [2] 38 da [2] 16 f8 [2] 02 e3 [2] 0d f9 [2] 13 e4 [2] 11 e5 [2] 0a e3 [2] 16 e4 [2] 0a cb }

  condition:
    any of them
}
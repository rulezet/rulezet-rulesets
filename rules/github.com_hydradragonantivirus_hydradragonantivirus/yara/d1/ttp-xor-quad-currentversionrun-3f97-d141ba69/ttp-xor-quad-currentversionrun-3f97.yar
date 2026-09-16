rule TTP_XOR_QUAD_CurrentVersionRun_3f97 {
  strings:
    $key_3f97 = { 6c f8 [2] 48 f6 [2] 63 da [2] 4d f8 [2] 59 e3 [2] 56 f9 [2] 48 e4 [2] 4a e5 [2] 51 e3 [2] 4d e4 [2] 51 cb }

  condition:
    any of them
}
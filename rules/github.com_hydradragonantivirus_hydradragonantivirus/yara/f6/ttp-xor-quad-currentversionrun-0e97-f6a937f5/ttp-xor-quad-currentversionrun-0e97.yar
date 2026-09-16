rule TTP_XOR_QUAD_CurrentVersionRun_0e97 {
  strings:
    $key_0e97 = { 5d f8 [2] 79 f6 [2] 52 da [2] 7c f8 [2] 68 e3 [2] 67 f9 [2] 79 e4 [2] 7b e5 [2] 60 e3 [2] 7c e4 [2] 60 cb }

  condition:
    any of them
}
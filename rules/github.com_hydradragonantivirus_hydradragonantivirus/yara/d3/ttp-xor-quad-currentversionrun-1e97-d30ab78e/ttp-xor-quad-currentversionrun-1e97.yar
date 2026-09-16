rule TTP_XOR_QUAD_CurrentVersionRun_1e97 {
  strings:
    $key_1e97 = { 4d f8 [2] 69 f6 [2] 42 da [2] 6c f8 [2] 78 e3 [2] 77 f9 [2] 69 e4 [2] 6b e5 [2] 70 e3 [2] 6c e4 [2] 70 cb }

  condition:
    any of them
}
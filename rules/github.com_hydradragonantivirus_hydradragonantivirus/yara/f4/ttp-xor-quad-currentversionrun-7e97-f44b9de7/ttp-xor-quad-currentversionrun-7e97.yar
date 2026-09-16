rule TTP_XOR_QUAD_CurrentVersionRun_7e97 {
  strings:
    $key_7e97 = { 2d f8 [2] 09 f6 [2] 22 da [2] 0c f8 [2] 18 e3 [2] 17 f9 [2] 09 e4 [2] 0b e5 [2] 10 e3 [2] 0c e4 [2] 10 cb }

  condition:
    any of them
}
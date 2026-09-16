rule TTP_XOR_QUAD_CurrentVersionRun_2e97 {
  strings:
    $key_2e97 = { 7d f8 [2] 59 f6 [2] 72 da [2] 5c f8 [2] 48 e3 [2] 47 f9 [2] 59 e4 [2] 5b e5 [2] 40 e3 [2] 5c e4 [2] 40 cb }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_4397 {
  strings:
    $key_4397 = { 10 f8 [2] 34 f6 [2] 1f da [2] 31 f8 [2] 25 e3 [2] 2a f9 [2] 34 e4 [2] 36 e5 [2] 2d e3 [2] 31 e4 [2] 2d cb }

  condition:
    any of them
}
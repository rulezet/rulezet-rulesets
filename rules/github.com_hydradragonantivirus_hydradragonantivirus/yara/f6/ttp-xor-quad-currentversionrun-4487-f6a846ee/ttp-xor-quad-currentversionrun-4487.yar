rule TTP_XOR_QUAD_CurrentVersionRun_4487 {
  strings:
    $key_4487 = { 17 e8 [2] 33 e6 [2] 18 ca [2] 36 e8 [2] 22 f3 [2] 2d e9 [2] 33 f4 [2] 31 f5 [2] 2a f3 [2] 36 f4 [2] 2a db }

  condition:
    any of them
}
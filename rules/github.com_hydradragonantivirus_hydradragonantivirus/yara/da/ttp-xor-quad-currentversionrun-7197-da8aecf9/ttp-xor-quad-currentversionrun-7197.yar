rule TTP_XOR_QUAD_CurrentVersionRun_7197 {
  strings:
    $key_7197 = { 22 f8 [2] 06 f6 [2] 2d da [2] 03 f8 [2] 17 e3 [2] 18 f9 [2] 06 e4 [2] 04 e5 [2] 1f e3 [2] 03 e4 [2] 1f cb }

  condition:
    any of them
}
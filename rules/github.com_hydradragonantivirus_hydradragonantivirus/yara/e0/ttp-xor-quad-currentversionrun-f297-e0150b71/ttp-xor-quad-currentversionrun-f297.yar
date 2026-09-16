rule TTP_XOR_QUAD_CurrentVersionRun_f297 {
  strings:
    $key_f297 = { a1 f8 [2] 85 f6 [2] ae da [2] 80 f8 [2] 94 e3 [2] 9b f9 [2] 85 e4 [2] 87 e5 [2] 9c e3 [2] 80 e4 [2] 9c cb }

  condition:
    any of them
}
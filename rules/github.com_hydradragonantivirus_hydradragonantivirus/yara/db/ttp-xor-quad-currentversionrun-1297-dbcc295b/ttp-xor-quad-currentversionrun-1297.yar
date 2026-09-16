rule TTP_XOR_QUAD_CurrentVersionRun_1297 {
  strings:
    $key_1297 = { 41 f8 [2] 65 f6 [2] 4e da [2] 60 f8 [2] 74 e3 [2] 7b f9 [2] 65 e4 [2] 67 e5 [2] 7c e3 [2] 60 e4 [2] 7c cb }

  condition:
    any of them
}
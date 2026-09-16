rule TTP_XOR_QUAD_CurrentVersionRun_4c97 {
  strings:
    $key_4c97 = { 1f f8 [2] 3b f6 [2] 10 da [2] 3e f8 [2] 2a e3 [2] 25 f9 [2] 3b e4 [2] 39 e5 [2] 22 e3 [2] 3e e4 [2] 22 cb }

  condition:
    any of them
}
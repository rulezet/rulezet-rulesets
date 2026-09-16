rule TTP_XOR_QUAD_CurrentVersionRun_4186 {
  strings:
    $key_4186 = { 12 e9 [2] 36 e7 [2] 1d cb [2] 33 e9 [2] 27 f2 [2] 28 e8 [2] 36 f5 [2] 34 f4 [2] 2f f2 [2] 33 f5 [2] 2f da }

  condition:
    any of them
}
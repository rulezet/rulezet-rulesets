rule TTP_XOR_QUAD_CurrentVersionRun_5d86 {
  strings:
    $key_5d86 = { 0e e9 [2] 2a e7 [2] 01 cb [2] 2f e9 [2] 3b f2 [2] 34 e8 [2] 2a f5 [2] 28 f4 [2] 33 f2 [2] 2f f5 [2] 33 da }

  condition:
    any of them
}
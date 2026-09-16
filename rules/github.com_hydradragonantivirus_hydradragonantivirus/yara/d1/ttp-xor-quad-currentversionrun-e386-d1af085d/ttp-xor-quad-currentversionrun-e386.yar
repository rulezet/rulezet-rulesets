rule TTP_XOR_QUAD_CurrentVersionRun_e386 {
  strings:
    $key_e386 = { b0 e9 [2] 94 e7 [2] bf cb [2] 91 e9 [2] 85 f2 [2] 8a e8 [2] 94 f5 [2] 96 f4 [2] 8d f2 [2] 91 f5 [2] 8d da }

  condition:
    any of them
}
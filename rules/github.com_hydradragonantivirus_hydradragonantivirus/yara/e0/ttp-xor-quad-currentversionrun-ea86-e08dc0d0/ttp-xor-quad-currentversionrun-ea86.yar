rule TTP_XOR_QUAD_CurrentVersionRun_ea86 {
  strings:
    $key_ea86 = { b9 e9 [2] 9d e7 [2] b6 cb [2] 98 e9 [2] 8c f2 [2] 83 e8 [2] 9d f5 [2] 9f f4 [2] 84 f2 [2] 98 f5 [2] 84 da }

  condition:
    any of them
}
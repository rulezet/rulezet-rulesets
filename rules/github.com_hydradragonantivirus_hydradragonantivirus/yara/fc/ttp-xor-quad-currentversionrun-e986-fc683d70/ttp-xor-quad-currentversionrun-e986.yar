rule TTP_XOR_QUAD_CurrentVersionRun_e986 {
  strings:
    $key_e986 = { ba e9 [2] 9e e7 [2] b5 cb [2] 9b e9 [2] 8f f2 [2] 80 e8 [2] 9e f5 [2] 9c f4 [2] 87 f2 [2] 9b f5 [2] 87 da }

  condition:
    any of them
}
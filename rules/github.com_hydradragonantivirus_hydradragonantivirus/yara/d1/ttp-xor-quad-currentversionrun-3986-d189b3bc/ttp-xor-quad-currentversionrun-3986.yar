rule TTP_XOR_QUAD_CurrentVersionRun_3986 {
  strings:
    $key_3986 = { 6a e9 [2] 4e e7 [2] 65 cb [2] 4b e9 [2] 5f f2 [2] 50 e8 [2] 4e f5 [2] 4c f4 [2] 57 f2 [2] 4b f5 [2] 57 da }

  condition:
    any of them
}
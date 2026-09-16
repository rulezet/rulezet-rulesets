rule TTP_XOR_QUAD_CurrentVersionRun_1f96 {
  strings:
    $key_1f96 = { 4c f9 [2] 68 f7 [2] 43 db [2] 6d f9 [2] 79 e2 [2] 76 f8 [2] 68 e5 [2] 6a e4 [2] 71 e2 [2] 6d e5 [2] 71 ca }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_2d9c {
  strings:
    $key_2d9c = { 7e f3 [2] 5a fd [2] 71 d1 [2] 5f f3 [2] 4b e8 [2] 44 f2 [2] 5a ef [2] 58 ee [2] 43 e8 [2] 5f ef [2] 43 c0 }

  condition:
    any of them
}
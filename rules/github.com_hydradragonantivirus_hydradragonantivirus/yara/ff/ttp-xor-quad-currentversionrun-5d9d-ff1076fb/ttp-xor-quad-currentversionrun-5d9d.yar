rule TTP_XOR_QUAD_CurrentVersionRun_5d9d {
  strings:
    $key_5d9d = { 0e f2 [2] 2a fc [2] 01 d0 [2] 2f f2 [2] 3b e9 [2] 34 f3 [2] 2a ee [2] 28 ef [2] 33 e9 [2] 2f ee [2] 33 c1 }

  condition:
    any of them
}
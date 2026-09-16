rule TTP_XOR_QUAD_CurrentVersionRun_1d9d {
  strings:
    $key_1d9d = { 4e f2 [2] 6a fc [2] 41 d0 [2] 6f f2 [2] 7b e9 [2] 74 f3 [2] 6a ee [2] 68 ef [2] 73 e9 [2] 6f ee [2] 73 c1 }

  condition:
    any of them
}
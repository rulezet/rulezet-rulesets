rule TTP_XOR_QUAD_CurrentVersionRun_1596 {
  strings:
    $key_1596 = { 46 f9 [2] 62 f7 [2] 49 db [2] 67 f9 [2] 73 e2 [2] 7c f8 [2] 62 e5 [2] 60 e4 [2] 7b e2 [2] 67 e5 [2] 7b ca }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_3c9b {
  strings:
    $key_3c9b = { 6f f4 [2] 4b fa [2] 60 d6 [2] 4e f4 [2] 5a ef [2] 55 f5 [2] 4b e8 [2] 49 e9 [2] 52 ef [2] 4e e8 [2] 52 c7 }

  condition:
    any of them
}
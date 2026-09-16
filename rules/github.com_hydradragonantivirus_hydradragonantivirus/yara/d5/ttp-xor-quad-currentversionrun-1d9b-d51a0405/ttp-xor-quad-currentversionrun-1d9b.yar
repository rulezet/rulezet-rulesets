rule TTP_XOR_QUAD_CurrentVersionRun_1d9b {
  strings:
    $key_1d9b = { 4e f4 [2] 6a fa [2] 41 d6 [2] 6f f4 [2] 7b ef [2] 74 f5 [2] 6a e8 [2] 68 e9 [2] 73 ef [2] 6f e8 [2] 73 c7 }

  condition:
    any of them
}
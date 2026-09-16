rule TTP_XOR_QUAD_CurrentVersionRun_6d9b {
  strings:
    $key_6d9b = { 3e f4 [2] 1a fa [2] 31 d6 [2] 1f f4 [2] 0b ef [2] 04 f5 [2] 1a e8 [2] 18 e9 [2] 03 ef [2] 1f e8 [2] 03 c7 }

  condition:
    any of them
}
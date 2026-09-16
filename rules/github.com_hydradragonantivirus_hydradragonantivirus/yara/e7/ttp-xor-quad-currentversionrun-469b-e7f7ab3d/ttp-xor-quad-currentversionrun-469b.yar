rule TTP_XOR_QUAD_CurrentVersionRun_469b {
  strings:
    $key_469b = { 15 f4 [2] 31 fa [2] 1a d6 [2] 34 f4 [2] 20 ef [2] 2f f5 [2] 31 e8 [2] 33 e9 [2] 28 ef [2] 34 e8 [2] 28 c7 }

  condition:
    any of them
}
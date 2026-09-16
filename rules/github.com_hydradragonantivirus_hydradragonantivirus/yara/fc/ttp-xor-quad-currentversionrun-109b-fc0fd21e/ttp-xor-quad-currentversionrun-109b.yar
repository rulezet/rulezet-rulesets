rule TTP_XOR_QUAD_CurrentVersionRun_109b {
  strings:
    $key_109b = { 43 f4 [2] 67 fa [2] 4c d6 [2] 62 f4 [2] 76 ef [2] 79 f5 [2] 67 e8 [2] 65 e9 [2] 7e ef [2] 62 e8 [2] 7e c7 }

  condition:
    any of them
}
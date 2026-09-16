rule TTP_XOR_QUAD_CurrentVersionRun_ef9b {
  strings:
    $key_ef9b = { bc f4 [2] 98 fa [2] b3 d6 [2] 9d f4 [2] 89 ef [2] 86 f5 [2] 98 e8 [2] 9a e9 [2] 81 ef [2] 9d e8 [2] 81 c7 }

  condition:
    any of them
}
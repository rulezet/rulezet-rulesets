rule TTP_XOR_QUAD_CurrentVersionRun_3f9b {
  strings:
    $key_3f9b = { 6c f4 [2] 48 fa [2] 63 d6 [2] 4d f4 [2] 59 ef [2] 56 f5 [2] 48 e8 [2] 4a e9 [2] 51 ef [2] 4d e8 [2] 51 c7 }

  condition:
    any of them
}
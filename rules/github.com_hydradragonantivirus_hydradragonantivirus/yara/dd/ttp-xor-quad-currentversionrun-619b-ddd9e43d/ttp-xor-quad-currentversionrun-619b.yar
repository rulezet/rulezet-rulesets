rule TTP_XOR_QUAD_CurrentVersionRun_619b {
  strings:
    $key_619b = { 32 f4 [2] 16 fa [2] 3d d6 [2] 13 f4 [2] 07 ef [2] 08 f5 [2] 16 e8 [2] 14 e9 [2] 0f ef [2] 13 e8 [2] 0f c7 }

  condition:
    any of them
}